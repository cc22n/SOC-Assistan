"""
Cliente mínimo de la API de Telegram para AVISOS SALIENTES (WP7 de PLAN-FUSION). Sin librería: solo `http_post`.

SEGURIDAD (verificado el 2026-11-20): el token del bot viaja DENTRO de la URL (`/bot<TOKEN>/sendMessage`) y aparece COMPLETO en el
texto de cualquier excepción de red (`ConnectionError`: "Max retries exceeded with url: /bot<TOKEN>/..."; `HTTPError`: "401 Client
Error: Unauthorized for url: https://api.telegram.org/bot<TOKEN>/..."). En SOC Agent el texto de las excepciones acaba en logs,
`feed_runs.error`, respuestas de la API y auditoría. Por eso:
  * NINGUNA excepción ni log de este módulo contiene el token: `redact()` se aplica a todo lo que sale de aquí, y `TelegramError`
    solo se construye con texto ya redactado.
  * Se redacta tanto el token configurado como cualquier cosa con forma de `bot<id>:<secreto>` (por si el token cambió o se pasó
    explícito), y los chats se enmascaran en los registros.

Telegram es un TERCERO y los bots no usan cifrado de extremo a extremo: solo debe enviarse información pública (CVE, KEV, EPSS).
El texto de NVD/KEV no es de confianza (lo escriben terceros): se escapa para `parse_mode=HTML`.
"""
import html
import logging
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence

from flask import current_app

from app.utils.http_client import http_post

logger = logging.getLogger(__name__)

API_URL = 'https://api.telegram.org/bot{token}/{method}'
MAX_CHARS = 4000            # el límite de Telegram es 4096; margen para el marcado
TIMEOUT = 15
_TOKEN_SHAPE = re.compile(r'bot\d{5,}:[A-Za-z0-9_\-]{10,}')          # bot<id>:<secreto>
_BARE_TOKEN = re.compile(r'\b\d{8,}:[A-Za-z0-9_\-]{30,}\b')           # <id>:<secreto> suelto


class TelegramError(RuntimeError):
    """Fallo al hablar con Telegram. El mensaje está YA redactado. `permanent`: no tiene sentido reintentar (token malo, chat
    inexistente, bot bloqueado); si es False (red, 429, 5xx) sí."""

    def __init__(self, message: str, *, permanent: bool = False, code: Optional[int] = None,
                 retry_after: Optional[int] = None):
        super().__init__(message)
        self.permanent = permanent
        self.code = code
        self.retry_after = retry_after


def redact(text: Any, token: Optional[str] = None) -> str:
    """Quita el token (el configurado, el explícito y cualquier cosa con su forma) de un texto."""
    out = str(text)
    for t in {token, _configured_token()}:
        if t:
            out = out.replace(t, '<TOKEN>')
    out = _TOKEN_SHAPE.sub('bot<TOKEN>', out)
    return _BARE_TOKEN.sub('<TOKEN>', out)


def mask_chat(chat_id: Any) -> str:
    """Chat id enmascarado para logs y auditoría (los últimos 3 dígitos)."""
    s = str(chat_id)
    return '…' + s[-3:] if len(s) > 3 else '…'


def _cfg(name: str, default=None):
    try:
        return current_app.config.get(name, default)
    except RuntimeError:
        return default


def _configured_token() -> Optional[str]:
    return _cfg('TELEGRAM_BOT_TOKEN')


def alert_chats() -> Sequence[int]:
    return tuple(_cfg('TELEGRAM_ALERT_CHAT_IDS', ()) or ())


def configured() -> bool:
    """Hay token Y al menos un chat permitido. Sin ambos el sistema se comporta exactamente como antes."""
    return bool(_configured_token() and alert_chats())


def escape(text: Any) -> str:
    """Escapa texto NO confiable para parse_mode=HTML."""
    return html.escape(str(text), quote=False)


def split_message(text: str, limit: int = MAX_CHARS) -> List[str]:
    """Trocea por líneas completas (cada línea lleva su propio marcado, así nunca se corta una etiqueta HTML por la mitad)."""
    if len(text) <= limit:
        return [text]
    chunks: List[str] = []
    current = ''
    for line in text.split('\n'):
        while len(line) > limit:                       # una sola línea gigante: corte duro
            if current:
                chunks.append(current)
                current = ''
            chunks.append(line[:limit])
            line = line[limit:]
        if len(current) + len(line) + 1 > limit and current:
            chunks.append(current)
            current = line
        else:
            current = f'{current}\n{line}' if current else line
    if current:
        chunks.append(current)
    return chunks


def _call(method: str, payload: Dict[str, Any], token: str) -> Dict[str, Any]:
    """POST a la API. Devuelve el JSON si ok=true; lanza TelegramError (redactado) en cualquier otro caso."""
    try:
        r = http_post(API_URL.format(token=token, method=method), json=payload, timeout=TIMEOUT)
    except Exception as e:                                        # red caída, DNS, timeout: el texto lleva la URL con el token
        raise TelegramError(f'sin conexión con Telegram: {redact(e, token)}') from None
    try:
        data = r.json()
    except ValueError:
        data = {}
    if r.status_code == 200 and isinstance(data, dict) and data.get('ok') is True:
        return data
    desc = redact((data or {}).get('description') or f'HTTP {r.status_code}', token) if isinstance(data, dict) else f'HTTP {r.status_code}'
    code = (data.get('error_code') if isinstance(data, dict) else None) or r.status_code
    retry_after = ((data.get('parameters') or {}).get('retry_after') if isinstance(data, dict) else None)
    # 400 (chat no encontrado / mensaje mal formado), 401 (token malo), 403 (bot bloqueado o expulsado): reintentar no sirve
    raise TelegramError(f'Telegram respondió {code}: {desc}', permanent=code in (400, 401, 403, 404),
                        code=code, retry_after=retry_after)


def send_message(chat_id: int, text: str, *, token: Optional[str] = None, disable_preview: bool = True) -> int:
    """Envía `text` (HTML) a un chat. Devuelve el nº de mensajes enviados (se trocea si excede el límite)."""
    token = token or _configured_token()
    if not token:
        raise TelegramError('TELEGRAM_BOT_TOKEN no configurado', permanent=True)
    chunks = split_message(text)
    for chunk in chunks:
        _call('sendMessage', {'chat_id': chat_id, 'text': chunk, 'parse_mode': 'HTML',
                              'disable_web_page_preview': disable_preview}, token)
    return len(chunks)


def send_to_chats(text: str, chat_ids: Optional[Iterable[int]] = None, *, token: Optional[str] = None) -> Dict[str, Any]:
    """
    Envía a cada chat PERMITIDO (por defecto, TELEGRAM_ALERT_CHAT_IDS; nunca a un chat arbitrario que no esté en la lista).
    Devuelve {'sent': [chat...], 'transient': [(chat, error)], 'permanent': [(chat, error)]} con los errores ya redactados.
    """
    permitidos = set(alert_chats())
    destino = [c for c in (chat_ids if chat_ids is not None else alert_chats()) if c in permitidos]
    result: Dict[str, Any] = {'sent': [], 'transient': [], 'permanent': []}
    for chat in destino:
        try:
            send_message(chat, text, token=token)
            result['sent'].append(chat)
        except TelegramError as e:
            logger.warning('Telegram: envío a %s falló (%s): %s', mask_chat(chat), 'permanente' if e.permanent else 'transitorio', e)
            result['permanent' if e.permanent else 'transient'].append((chat, str(e)))
    return result


def get_me(token: Optional[str] = None) -> Dict[str, Any]:
    """Comprueba el token (devuelve los datos públicos del bot). Para `flask telegram test`."""
    token = token or _configured_token()
    if not token:
        raise TelegramError('TELEGRAM_BOT_TOKEN no configurado', permanent=True)
    return _call('getMe', {}, token).get('result', {})
