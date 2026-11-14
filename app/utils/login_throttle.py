"""
Bloqueo temporal de cuenta por intentos de login fallidos (credential stuffing distribuido).

El rate limit de /auth/login es por IP; un atacante con muchas IPs puede seguir probando
contraseñas contra UNA cuenta. Este módulo cuenta los fallos por nombre de usuario
(independiente de la IP) usando la propia auditoría (`audit_events`), sin migración ni
infraestructura nueva y con la misma persistencia entre workers.

Reglas:
  * LOCKOUT_THRESHOLD fallos en LOCKOUT_WINDOW bloquean el login de ese nombre de usuario.
  * El bloqueo es una ventana deslizante: expira solo cuando el fallo nº THRESHOLD más
    reciente sale de la ventana (máximo LOCKOUT_WINDOW desde el último fallo contado).
  * Los intentos DURANTE el bloqueo no se cuentan ('login_blocked', no 'login_failed'), así
    que un atacante no puede prolongarlo indefinidamente.
  * Un login correcto reinicia la cuenta.
  * Se cuenta por nombre intentado EXISTA O NO la cuenta, para que el bloqueo no revele qué
    usuarios existen.
"""
from datetime import timedelta
from typing import Optional

from sqlalchemy import func

from app import db
from app.models.audit import AuditEvent
from app.utils.time_utils import utcnow

LOCKOUT_THRESHOLD = 5
LOCKOUT_WINDOW = timedelta(minutes=15)
MAX_USERNAME_LEN = 80          # evita filas de auditoría gigantes con usernames enormes


def normalize_username(username: Optional[str]) -> str:
    return (username or '').strip()[:MAX_USERNAME_LEN].lower()


def _window_start(key: str, now):
    since = now - LOCKOUT_WINDOW
    last_ok = db.session.query(func.max(AuditEvent.created_at)).filter(
        AuditEvent.action == 'login',
        AuditEvent.success.is_(True),
        func.lower(AuditEvent.username) == key,
    ).scalar()
    return last_ok if (last_ok and last_ok > since) else since


def lockout_remaining(username: Optional[str], now=None) -> Optional[timedelta]:
    """Tiempo que falta para que expire el bloqueo, o None si la cuenta NO está bloqueada."""
    key = normalize_username(username)
    if not key:
        return None
    now = now or utcnow()
    since = _window_start(key, now)
    rows = (
        db.session.query(AuditEvent.created_at)
        .filter(
            AuditEvent.action == 'login_failed',
            AuditEvent.created_at > since,
            # trim + lower: el nombre se guarda tal como se escribió (truncado), y la clave está normalizada
            func.lower(func.trim(AuditEvent.details['username'].astext)) == key,
        )
        .order_by(AuditEvent.created_at.desc())
        .limit(LOCKOUT_THRESHOLD)
        .all()
    )
    if len(rows) < LOCKOUT_THRESHOLD:
        return None
    unlock_at = rows[LOCKOUT_THRESHOLD - 1][0] + LOCKOUT_WINDOW
    remaining = unlock_at - now
    return remaining if remaining > timedelta(0) else None


def is_locked(username: Optional[str], now=None) -> bool:
    return lockout_remaining(username, now) is not None


def minutes_left(remaining: timedelta) -> int:
    """Minutos (redondeados hacia arriba, mínimo 1) para mostrar al usuario."""
    return max(1, int(-(-remaining.total_seconds() // 60)))
