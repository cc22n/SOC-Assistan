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
  * Un administrador puede desbloquear manualmente (`unlock_account`): se registra un evento
    'account_unlocked' y la cuenta se reinicia igual que con un login correcto. La auditoría es de solo
    inserción: desbloquear = AÑADIR un evento, nunca borrar los fallos (el rastro del ataque se conserva).
  * Se cuenta por nombre intentado EXISTA O NO la cuenta, para que el bloqueo no revele qué
    usuarios existen.
"""
from datetime import timedelta
from typing import Optional

from sqlalchemy import and_, func, or_

from app import db
from app.models.audit import AuditEvent
from app.utils.time_utils import utcnow

LOCKOUT_THRESHOLD = 5
LOCKOUT_WINDOW = timedelta(minutes=15)
MAX_USERNAME_LEN = 80          # evita filas de auditoría gigantes con usernames enormes


def normalize_username(username: Optional[str]) -> str:
    return (username or '').strip()[:MAX_USERNAME_LEN].lower()


def _window_start(key: str, now):
    """Inicio de la ventana de conteo: lo más reciente entre (ahora - ventana), el último login correcto
    y el último desbloqueo manual de ese nombre de usuario."""
    since = now - LOCKOUT_WINDOW
    ultimo_reinicio = db.session.query(func.max(AuditEvent.created_at)).filter(
        or_(
            and_(AuditEvent.action == 'login',
                 AuditEvent.success.is_(True),
                 func.lower(AuditEvent.username) == key),
            and_(AuditEvent.action == 'account_unlocked',
                 func.lower(func.trim(AuditEvent.details['username'].astext)) == key),
        )
    ).scalar()
    return ultimo_reinicio if (ultimo_reinicio and ultimo_reinicio > since) else since


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


def _failures_since(key: str, since):
    """Consulta base: fallos de login de ese nombre (normalizado) posteriores a `since`."""
    return db.session.query(AuditEvent).filter(
        AuditEvent.action == 'login_failed',
        AuditEvent.created_at > since,
        func.lower(func.trim(AuditEvent.details['username'].astext)) == key,
    )


def locked_accounts(now=None):
    """
    Cuentas bloqueadas AHORA. Cada elemento: username (normalizado), restante (minutos, entero >= 1),
    fallos (cuántos cuentan en la ventana), ultimo_fallo (ISO) y ultima_ip (de ese último fallo).
    Se calcula con la misma regla que el login (`lockout_remaining`), no con una aproximación.
    """
    now = now or utcnow()
    candidatos = (
        db.session.query(func.lower(func.trim(AuditEvent.details['username'].astext)))
        .filter(AuditEvent.action == 'login_failed', AuditEvent.created_at > now - LOCKOUT_WINDOW)
        .distinct().all()
    )
    out = []
    for (key,) in candidatos:
        if not key:
            continue
        restante = lockout_remaining(key, now)
        if restante is None:
            continue
        since = _window_start(key, now)
        q = _failures_since(key, since)
        ultimo = q.order_by(AuditEvent.created_at.desc()).first()
        out.append({
            'username': key,
            'restante_min': minutes_left(restante),
            'fallos': q.count(),
            'ultimo_fallo': ultimo.created_at.isoformat() if ultimo else None,
            'ultima_ip': ultimo.ip_address if ultimo else None,
        })
    out.sort(key=lambda x: x['restante_min'], reverse=True)
    return out


def unlock_account(username: Optional[str], by: Optional[str] = None, commit: bool = True) -> dict:
    """
    Desbloquea manualmente un nombre de usuario (y reinicia su contador de fallos).

    Registra SIEMPRE un evento 'account_unlocked' (aunque la cuenta no estuviera bloqueada: queda constancia de
    quién reinició el contador). Si el evento NO se puede guardar lanza RuntimeError: `AuditEvent.log` falla en
    silencio, y aquí un fallo silencioso dejaría la cuenta bloqueada mientras el administrador cree haberla
    desbloqueado.

    Args:
        by: quién lo hace cuando no hay sesión web (p.ej. 'cli:coral'). En una petición se toma del usuario actual.
    Returns: {'username': <normalizado>, 'was_locked': bool}
    """
    key = normalize_username(username)
    if not key:
        raise ValueError('username vacío')
    was_locked = lockout_remaining(key) is not None
    evento = AuditEvent.log(
        'account_unlocked',
        resource_type='user',
        details={'username': key, 'was_locked': was_locked, 'by': by},
        username=by,                        # solo se usa si no hay usuario autenticado en la petición
        _commit=commit,
    )
    if evento is None:
        raise RuntimeError('no se pudo registrar el desbloqueo en la auditoría; la cuenta NO se ha desbloqueado')
    return {'username': key, 'was_locked': was_locked}
