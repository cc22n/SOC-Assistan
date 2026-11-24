"""
Redactado de secretos en TEXTO (hallazgos A2 y A3 de prelaunch-report-4, verificados con ejecución).

El texto de una excepción de `requests` lleva la URL COMPLETA, con la clave de API si viaja en la query
("Max retries exceeded with url: /shodan/host/8.8.8.8?key=SECRETO"). Los clientes de las 25 APIs hacen `logger.error(f"... {e}")` y
`return {'error': str(e)}`: la clave terminaba en el log, en la columna `*_data` de la BD, en la respuesta JSON, en exports y en el prompt
a un LLM de terceros. Basta una caída de red o un 502/503 reintentado.

Un solo sitio, tres usos:
  * `http_client` re-lanza las excepciones de `requests` con el mensaje YA redactado (el punto único por el que sale todo el tráfico);
  * `SecretRedactingFilter` en los handlers de logging (urllib3 también registra la URL con la clave al reintentar);
  * `sentry_scrub` (breadcrumbs, transacciones y eventos).

Qué redacta (en este orden):
  1. el VALOR de cada secreto configurado (variables de entorno o config cuyo nombre acaba en _KEY/_TOKEN/_SECRET/_PASSWORD/_DSN...):
     es lo más fiable, no depende de cómo viaje la clave;
  2. el token de Telegram con su forma (`/bot<id>:<secreto>`);
  3. parámetros sensibles de query (`key=`, `apikey=`, `token=`, `secret=`...);
  4. `Bearer <valor>` y la contraseña de una URL `scheme://usuario:CLAVE@host`.
"""
import logging
import os
import re
import time
import traceback
from typing import Any, FrozenSet

REDACTED = '<REDACTED>'
MIN_SECRET_LEN = 8
_TTL = 30.0                                                     # los secretos configurados no cambian en caliente: se cachean

_SECRET_NAME = re.compile(r'(?:_KEYS?|_TOKEN|_SECRET|_PASSWORD|_PASSWD|_DSN|_APIKEY)$')
_NOT_SECRETS = {'PUBLIC_KEY'}
_TELEGRAM_SHAPE = re.compile(r'bot\d{5,}:[A-Za-z0-9_\-]{10,}')
_TELEGRAM_BARE = re.compile(r'\b\d{8,}:[A-Za-z0-9_\-]{30,}\b')
_QUERY = re.compile(r'(?i)((?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|auth[_-]?key|token|key|secret|password|passwd|signature|sig)=)'
                    r'[^&\s"\'<>]+')
_BEARER = re.compile(r'(?i)\b(bearer\s+)[A-Za-z0-9._~+/=\-]{8,}')
_URL_PASSWORD = re.compile(r'(://[^:/@\s]+:)[^@\s]+(@)')

_cache = {'at': 0.0, 'secrets': frozenset()}


def _collect() -> FrozenSet[str]:
    found = set()

    def add(name: str, value: Any):
        if not isinstance(name, str) or not isinstance(value, str):
            return
        n = name.upper()
        if n in _NOT_SECRETS or not (_SECRET_NAME.search(n) or n in ('SECRET_KEY',)):
            return
        for part in value.split(','):                           # AUDIT_CHAIN_PREVIOUS_KEYS y similares: lista separada por comas
            part = part.strip()
            if len(part) >= MIN_SECRET_LEN:
                found.add(part)

    for k, v in os.environ.items():
        add(k, v)
    try:
        from flask import current_app
        for k, v in current_app.config.items():
            add(k, v)
    except RuntimeError:                                        # fuera de contexto de aplicación
        pass
    return frozenset(found)


def configured_secrets() -> FrozenSet[str]:
    now = time.monotonic()
    if now - _cache['at'] > _TTL:
        _cache['secrets'] = _collect()
        _cache['at'] = now
    return _cache['secrets']


def reset_cache() -> None:
    """Fuerza a releer los secretos configurados (tests; o tras cambiar la configuración en caliente)."""
    _cache['at'] = 0.0


def redact_secrets(value: Any) -> str:
    out = value if isinstance(value, str) else str(value)
    for s in sorted(configured_secrets(), key=len, reverse=True):
        if s in out:
            out = out.replace(s, REDACTED)
    out = _TELEGRAM_SHAPE.sub('bot' + REDACTED, out)
    out = _TELEGRAM_BARE.sub(REDACTED, out)
    out = _QUERY.sub(lambda m: m.group(1) + REDACTED, out)
    out = _BEARER.sub(lambda m: m.group(1) + REDACTED, out)
    return _URL_PASSWORD.sub(lambda m: m.group(1) + REDACTED + m.group(2), out)


class SecretRedactingFilter(logging.Filter):
    """Redacta mensaje y traza de CADA registro antes de que llegue a un handler (archivo, stdout de Docker...). Nunca lanza."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
            red = redact_secrets(msg)
            if red != msg:
                record.msg, record.args = red, ()
            if record.exc_info and record.exc_info[1] is not None:
                texto = ''.join(traceback.format_exception(*record.exc_info))
                rojo = redact_secrets(texto)
                if rojo != texto:
                    # El Formatter estándar y JSONFormatter usan `exc_text` cuando no hay `exc_info`
                    record.exc_text, record.exc_info = rojo.rstrip('\n'), None
        except Exception:                                       # un fallo del redactado no puede tumbar el logging
            pass
        return True


def install_log_redaction(*handler_groups) -> int:
    """Añade el filtro (una sola vez) a todos los handlers dados. También a los de los loggers de urllib3 que imprimen la URL con la clave
    al reintentar (se filtran a nivel de LOGGER porque los filtros de un logger no se heredan). Devuelve cuántos tocó."""
    n = 0
    for group in handler_groups:
        for h in group:
            if not any(isinstance(f, SecretRedactingFilter) for f in h.filters):
                h.addFilter(SecretRedactingFilter())
                n += 1
    for name in ('urllib3.connectionpool', 'urllib3.util.retry', 'urllib3.poolmanager'):
        lg = logging.getLogger(name)
        if not any(isinstance(f, SecretRedactingFilter) for f in lg.filters):
            lg.addFilter(SecretRedactingFilter())
            n += 1
    return n
