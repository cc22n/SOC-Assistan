"""
Avisos de los feeds por Telegram (WP7 de PLAN-FUSION, v1: solo avisos SALIENTES).

Qué avisa: CVE RELEVANTES para el stack (`is_relevant`) con riesgo >= TELEGRAM_MIN_RISK (por defecto ALTO, que incluye siempre los de
KEV por su suelo) que aún no se han avisado (`notified_at` NULL) y se tocaron en los últimos TELEGRAM_BACKLOG_DAYS (al activarlo, no se
inunda con el histórico). Un CVE ya conocido que se ESCALA a KEV vuelve a quedar pendiente (lo decide `feed_runner.upsert_item`).

Cuándo se marca como avisado (`notified_at`):
  * al menos UN chat lo recibió, Y
  * ningún chat falló de forma TRANSITORIA (red, 429, 5xx): si falla uno, no se marca y se reintenta (un chat que ya lo recibió puede
    recibirlo dos veces: se prefiere un duplicado a perder una alerta), y
  * un fallo PERMANENTE de un chat (bot bloqueado, chat inexistente) no bloquea al resto: reintentar no lo arreglaría y repetiría el
    aviso a los demás en cada ciclo.
  Si NADIE lo recibió (token malo, todos los chats inalcanzables) no se marca nada: no se pierden avisos en silencio.

Solo sale información PÚBLICA (CVE, KEV, EPSS). El texto de NVD/KEV se escapa (no es de confianza).
"""
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from flask import current_app

from app import db
from app.models.feed import FeedItem, TechStackEntry
from app.services import telegram_client
from app.utils.time_utils import utcnow

logger = logging.getLogger(__name__)

RISK_ORDER = ['LIMPIO', 'BAJO', 'MEDIO', 'ALTO', 'CRÍTICO']
MAX_ITEMS_PER_MESSAGE = 10
RETRY_BACKOFF = timedelta(minutes=10)           # tras un fallo no se vuelve a intentar en cada ciclo del daemon (5 min)
_next_attempt: Optional[datetime] = None        # por proceso: el daemon es uno solo


def _cfg(name: str, default=None):
    return current_app.config.get(name, default)


def min_risk() -> str:
    r = str(_cfg('TELEGRAM_MIN_RISK', 'ALTO')).upper().replace('CRITICO', 'CRÍTICO')
    return r if r in RISK_ORDER else 'ALTO'


def pending_items(now: Optional[datetime] = None) -> List[FeedItem]:
    now = now or utcnow()
    niveles = RISK_ORDER[RISK_ORDER.index(min_risk()):]
    desde = now - timedelta(days=int(_cfg('TELEGRAM_BACKLOG_DAYS', 3)))
    return (FeedItem.query.filter(FeedItem.is_relevant.is_(True), FeedItem.notified_at.is_(None),
                                  FeedItem.risk_level.in_(niveles), FeedItem.updated_at >= desde)
            .order_by(FeedItem.priority_score.desc(), FeedItem.published_at.desc().nullslast(), FeedItem.id.desc()).all())


def _marker(item: FeedItem) -> str:
    if item.in_kev:
        return '🔴 KEV' + (' · ransomware' if item.known_ransomware else '') + (' · escalado' if item.escalated_at else '')
    return '🟠' if item.risk_level == 'ALTO' else '⚫' if item.risk_level == 'CRÍTICO' else '🟡'


def format_message(items: List[FeedItem], total_pending: int, base_url: str = '',
                   labels: Optional[Dict[int, str]] = None) -> str:
    e = telegram_client.escape
    n = len(items)
    lines = [f'<b>SOC Agent: {total_pending} CVE afecta{"n" if total_pending != 1 else ""} a tu stack</b>']
    for it in items:
        quien = ', '.join(sorted({(labels or {}).get(i, '') for i in (it.matched_entries or []) if (labels or {}).get(i)})) or \
            ', '.join(f"{a.get('vendor') or ''} {a.get('product') or ''}".strip() for a in (it.affected or [])[:2])
        extra = f' · CVSS {it.cvss_score:g}' if it.cvss_score is not None else ''
        extra += f' · EPSS {it.epss * 100:.0f}%' if it.epss is not None else ''
        titulo = (it.title or '').strip()
        lines.append('')
        lines.append(f'{_marker(it)} <b>{e(it.cve_id)}</b> · {e(it.risk_level)}{extra}')
        if titulo:
            lines.append(e(titulo[:160] + ('…' if len(titulo) > 160 else '')))
        if quien:
            lines.append(f'Afecta a: {e(quien[:120])}')
        if base_url:
            href = telegram_client.escape(f'{base_url}/analyze?ioc={it.cve_id}&type=cve')
            lines.append(f'<a href="{href}">Analizar</a>')
    if total_pending > n:
        lines.append('')
        lines.append(f'…y {total_pending - n} más' + (f' en {e(base_url)}/feeds' if base_url else ' en /feeds'))
    return '\n'.join(lines)


def notify_pending(now: Optional[datetime] = None) -> Dict[str, Any]:
    """Envía lo pendiente. Devuelve {'status': disabled|idle|sent|retry|undeliverable, 'items': n, ...}. Nunca lanza."""
    if not telegram_client.configured():
        return {'status': 'disabled', 'items': 0}
    now = now or utcnow()
    try:
        items = pending_items(now)
        if not items:
            return {'status': 'idle', 'items': 0}
        shown = items[:MAX_ITEMS_PER_MESSAGE]
        labels = {e.id: e.label() for e in TechStackEntry.query.all()}
        text = format_message(shown, len(items), _cfg('APP_BASE_URL', ''), labels)
        res = telegram_client.send_to_chats(text)
        chats = [telegram_client.mask_chat(c) for c in telegram_client.alert_chats()]
        resumen = {'items': len(shown), 'pendientes': len(items), 'recibieron': len(res['sent']),
                   'transitorios': len(res['transient']), 'permanentes': len(res['permanent'])}
        if res['transient']:
            return {'status': 'retry', **resumen}
        if not res['sent']:
            logger.error('Telegram: NADIE recibió el aviso (¿token inválido o chats inalcanzables?); no se marca nada')
            return {'status': 'undeliverable', **resumen}
        for it in shown:
            it.notified_at = now
        from app.models.audit import AuditEvent
        AuditEvent.log('telegram_alert_sent', resource_type='feed', success=True,
                       details={'cves': [i.cve_id for i in shown], 'chats': chats, **resumen})
        db.session.commit()
        return {'status': 'sent', **resumen}
    except Exception as e:                                       # un aviso fallido no puede romper el ciclo del daemon
        db.session.rollback()
        logger.error('feed_notifier: %s', telegram_client.redact(e))
        return {'status': 'retry', 'items': 0, 'error': telegram_client.redact(e)}


def maybe_notify(now: Optional[datetime] = None) -> Dict[str, Any]:
    """`notify_pending` con espera tras un fallo (por proceso). Es lo que llama el daemon en cada ciclo."""
    global _next_attempt
    now = now or utcnow()
    if _next_attempt is not None and now < _next_attempt:
        return {'status': 'backoff', 'items': 0}
    r = notify_pending(now)
    _next_attempt = now + RETRY_BACKOFF if r['status'] in ('retry', 'undeliverable') else None
    return r


def reset_backoff() -> None:
    """Solo para tests."""
    global _next_attempt
    _next_attempt = None
