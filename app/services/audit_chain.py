"""
Cadena criptográfica de la auditoría (WP1 de PLAN-FUSION).

Cada `AuditEvent` se SELLA AL INSERTARSE con `entry_hash = HMAC-SHA256(clave, canónico(fila) + prev_hash + posición)`, encadenado al
anterior. Quien tenga solo la BD (SQL inyectado, credenciales robadas, un backup manipulado) no puede editar, borrar, insertar ni
reordenar eventos sin que `verify_chain` lo detecte, porque no puede recalcular el HMAC (la clave `AUDIT_CHAIN_KEY` vive fuera de la BD).

Límites que hay que conocer (no son fallos, son lo que esta defensa NO cubre):
  * Quien tenga la CLAVE puede falsificar la cadena entera. Por eso el ancla externa (`anchor`/Telegram): un testigo fuera del servidor.
  * Truncar las ÚLTIMAS filas solo lo detecta el ancla (una cadena más corta que el ancla publicado), nunca la cadena sola.
  * Sin clave (desarrollo/test) el hash es SHA-256 simple (`key_id='none'`): solo detecta ediciones torpes. En producción la clave es
    obligatoria (`ProductionConfig.init_app`).
  * No protege lo que la aplicación decida no auditar.

Se sella en `before_flush` (no en `before_insert`): así varios eventos del mismo flush se encadenan entre sí en orden de creación.
Se toma `pg_advisory_xact_lock` (se libera solo al commit/rollback) para serializar a los 3 workers de Gunicorn, el daemon y la CLI;
`UNIQUE(chain_pos)` es la red de seguridad. Una transacción que audita y luego espera una fila que tiene otra transacción podría
interbloquearse con ella (PostgreSQL aborta una): por eso toda llamada a `AuditEvent.log` comitea enseguida (`_commit=True`).

El hash cubre TODAS las columnas persistidas salvo `id` (lo asigna la BD al insertar) y `user_id` (la FK es ON DELETE SET NULL: borrar
un usuario lo pone a NULL; `username` es su copia desnormalizada y sí entra).
"""
import hashlib
import hmac
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from flask import current_app
from sqlalchemy import event, text
from sqlalchemy.orm import Session, attributes

from app import db
from app.models.audit import AuditEvent
from app.utils.time_utils import utcnow

logger = logging.getLogger(__name__)

GENESIS = '0' * 64
ALGO_LIVE = 'v1'
ALGO_LEGACY = 'v1-legacy'              # fila anterior a la cadena, sellada a posteriori con `flask audit seal-legacy`
ALGOS = (ALGO_LIVE, ALGO_LEGACY)
LOCK_KEY = 0x50C0A0D17                 # clave del advisory lock (bigint fijo)
ANCHOR_ACTION = 'audit_anchor_sent'
ANCHOR_EVERY = timedelta(hours=24)
RETRY_BACKOFF = timedelta(minutes=10)

# El trigger se instala desde la migración (b…_audit_chain); esta copia sirve a los tests (que comprueban que son idénticas).
GUARD_FUNCTION_SQL = """
CREATE OR REPLACE FUNCTION audit_events_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'audit_events es de solo agregar: DELETE no permitido';
    END IF;
    -- UPDATE: solo se permite (a) que la FK ON DELETE SET NULL ponga user_id a NULL y (b) sellar una fila de legado (chain_* de NULL a valor)
    IF ROW(NEW.id, NEW.username, NEW.action, NEW.resource_type, NEW.resource_id, NEW.details, NEW.ip_address,
           NEW.user_agent, NEW.request_id, NEW.success, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.username, OLD.action, OLD.resource_type, OLD.resource_id, OLD.details, OLD.ip_address,
           OLD.user_agent, OLD.request_id, OLD.success, OLD.created_at) THEN
        RAISE EXCEPTION 'audit_events es de solo agregar: UPDATE no permitido';
    END IF;
    IF NEW.user_id IS DISTINCT FROM OLD.user_id AND NEW.user_id IS NOT NULL THEN
        RAISE EXCEPTION 'audit_events es de solo agregar: user_id solo puede pasar a NULL';
    END IF;
    IF OLD.entry_hash IS NOT NULL
       AND ROW(NEW.chain_pos, NEW.prev_hash, NEW.entry_hash, NEW.key_id, NEW.algo)
           IS DISTINCT FROM ROW(OLD.chain_pos, OLD.prev_hash, OLD.entry_hash, OLD.key_id, OLD.algo) THEN
        RAISE EXCEPTION 'audit_events es de solo agregar: una fila sellada no se puede resellar';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""
GUARD_TRIGGER_SQL = ("CREATE TRIGGER trg_audit_events_guard BEFORE UPDATE OR DELETE ON audit_events "
                     "FOR EACH ROW EXECUTE FUNCTION audit_events_guard()")


# ============================================================================ clave y canónico

def get_key() -> Optional[bytes]:
    k = current_app.config.get('AUDIT_CHAIN_KEY')
    return k.encode('utf-8') if k else None


def previous_keys() -> Dict[str, bytes]:
    """Claves ANTERIORES declaradas para la rotación (AUDIT_CHAIN_PREVIOUS_KEYS, separadas por coma): {key_id: clave}."""
    raw = current_app.config.get('AUDIT_CHAIN_PREVIOUS_KEYS') or ''
    return {key_id(k.strip().encode('utf-8')): k.strip().encode('utf-8') for k in raw.split(',') if k.strip()}


def lost_key_ids() -> Dict[str, int]:
    """
    Claves PERDIDAS que el operador declara: AUDIT_CHAIN_LOST_KEY_IDS=<key_id>:<última_posición>[,...] -> {key_id: tope}.
    El TOPE es obligatorio (prelaunch-report-4 M2): una fila de esa clave por ENCIMA del tope es rotura. Sin tope, quien tuviera INSERT
    sobre `audit_events` (una inyección SQL) podría añadir filas falsas con ese key_id público, que la verificación aceptaría como
    "sin poder recalcular". Una entrada sin tope válido se IGNORA (y se avisa): las filas siguen siendo rotura.
    """
    raw = current_app.config.get('AUDIT_CHAIN_LOST_KEY_IDS') or ''
    out: Dict[str, int] = {}
    for item in raw.split(','):
        item = item.strip().lower()
        if not item:
            continue
        kid, _, cap = item.partition(':')
        if kid and cap.strip().isdigit() and int(cap) >= 1:
            out[kid] = int(cap)
        else:
            logger.warning("AUDIT_CHAIN_LOST_KEY_IDS: entrada %r ignorada: el formato es <key_id>:<ultima_posicion>", item)
    return out


def accept_unkeyed_cap() -> Optional[int]:
    """AUDIT_CHAIN_ACCEPT_UNKEYED=<última_posición>: hasta ahí se acepta histórico sellado SIN clave (la clave se añadió tarde). Con tope
    por la misma razón que las claves perdidas (SHA-256 sin clave es forjable en cualquier posición). 'true' ya no vale."""
    raw = str(current_app.config.get('AUDIT_CHAIN_ACCEPT_UNKEYED') or '').strip()
    if raw.isdigit() and int(raw) >= 1:
        return int(raw)
    if raw:
        logger.warning("AUDIT_CHAIN_ACCEPT_UNKEYED=%r ignorado: debe ser la ultima posicion sin clave (un numero)", raw)
    return None


def key_id(key: Optional[bytes]) -> str:
    """Huella pública de la clave (no la revela): permite detectar que cambió. 'none' = sin clave (SHA-256 simple)."""
    return hashlib.sha256(key).hexdigest()[:8] if key else 'none'


def _norm(v: Any) -> Any:
    """Normaliza lo que JSONB no conserva igual (1e22 float vuelve como int): así el hash es el mismo antes y después de la BD."""
    if isinstance(v, dict):
        return {str(k): _norm(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_norm(x) for x in v]
    if isinstance(v, float) and v == v and v not in (float('inf'), float('-inf')) and v.is_integer():
        return int(v)
    return v


def _created_iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.isoformat(timespec='microseconds')


def canonical(fields: Dict[str, Any]) -> str:
    """Representación canónica y determinista de la fila (v1)."""
    f = {
        'username': fields.get('username'), 'action': fields.get('action'), 'resource_type': fields.get('resource_type'),
        'resource_id': fields.get('resource_id'), 'details': _norm(fields.get('details')),
        'ip_address': fields.get('ip_address'), 'user_agent': fields.get('user_agent'), 'request_id': fields.get('request_id'),
        'success': bool(fields.get('success')), 'created_at': _created_iso(fields.get('created_at')),
    }
    return json.dumps(f, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def compute_hash(key: Optional[bytes], pos: int, prev_hash: str, fields: Dict[str, Any]) -> str:
    msg = f'{pos}|{prev_hash}|{canonical(fields)}'.encode('utf-8')
    return hmac.new(key, msg, hashlib.sha256).hexdigest() if key else hashlib.sha256(msg).hexdigest()


def _fields_of(obj) -> Dict[str, Any]:
    return {c: getattr(obj, c) for c in ('username', 'action', 'resource_type', 'resource_id', 'details', 'ip_address',
                                          'user_agent', 'request_id', 'success', 'created_at')}


# ============================================================================ sellado al insertar

def _lock_and_tail(session: Session):
    """Toma el bloqueo de la cadena (hasta el fin de la transacción) y devuelve (posición, hash) del último eslabón."""
    if session.get_bind().dialect.name == 'postgresql':
        session.execute(text('SELECT pg_advisory_xact_lock(:k)'), {'k': LOCK_KEY})
    row = session.execute(text('SELECT chain_pos, entry_hash FROM audit_events WHERE chain_pos IS NOT NULL '
                               'ORDER BY chain_pos DESC LIMIT 1')).first()
    return (row[0], row[1]) if row else (0, GENESIS)


def seal_new_events(session: Session, flush_context=None, instances=None) -> None:
    """before_flush: sella los AuditEvent nuevos, en orden de creación, encadenados al último eslabón confirmado."""
    nuevos = [o for o in session.new if isinstance(o, AuditEvent)]
    if not nuevos:
        return
    nuevos.sort(key=lambda o: attributes.instance_state(o).insert_order or 0)
    key = get_key()
    kid = key_id(key)
    if not key:
        _warn_no_key()
    with session.no_autoflush:
        pos, prev = _lock_and_tail(session)
        for o in nuevos:
            o.created_at = o.created_at or utcnow()
            if o.created_at.tzinfo is not None:
                o.created_at = o.created_at.astimezone(timezone.utc).replace(tzinfo=None)
            if o.success is None:
                o.success = True
            pos += 1
            o.chain_pos, o.prev_hash, o.key_id, o.algo = pos, prev, kid, ALGO_LIVE
            o.entry_hash = compute_hash(key, pos, prev, _fields_of(o))
            prev = o.entry_hash


_warned = False


def _warn_no_key() -> None:
    global _warned
    if not _warned:
        _warned = True
        logger.warning('AUDIT_CHAIN_KEY no definida: la cadena de auditoría usa SHA-256 SIN clave (solo detecta ediciones torpes). '
                       'En producción es obligatoria.')


def install_listeners() -> None:
    if not event.contains(Session, 'before_flush', seal_new_events):
        event.listen(Session, 'before_flush', seal_new_events)


# ============================================================================ verificación

def _fields_from_row(r) -> Dict[str, Any]:
    return {'username': r.username, 'action': r.action, 'resource_type': r.resource_type, 'resource_id': r.resource_id,
            'details': r.details, 'ip_address': r.ip_address, 'user_agent': r.user_agent, 'request_id': r.request_id,
            'success': r.success, 'created_at': r.created_at}


def tail() -> Optional[Dict[str, Any]]:
    row = db.session.execute(text('SELECT chain_pos, entry_hash FROM audit_events WHERE chain_pos IS NOT NULL '
                                  'ORDER BY chain_pos DESC LIMIT 1')).first()
    return {'pos': row[0], 'hash': row[1]} if row else None


def parse_anchor(value: str) -> tuple:
    try:
        pos, h = value.strip().split(':', 1)
        pos = int(pos)
    except (ValueError, AttributeError):
        raise ValueError('el ancla debe tener la forma <posición>:<hash>')
    h = h.strip().lower()
    if pos < 1 or len(h) != 64 or any(c not in '0123456789abcdef' for c in h):
        raise ValueError('el ancla debe tener la forma <posición>:<hash de 64 hex>')
    return pos, h


def verify_chain(anchor: Optional[str] = None, batch: int = 2000) -> Dict[str, Any]:
    """
    Recorre la cadena por posición y recalcula cada eslabón. Devuelve:
      {'ok', 'checked', 'broken': {'pos', 'id', 'reason'} | None (la PRIMERA rota), 'unverifiable', 'unsealed', 'tail', 'key_id', 'anchor'}
    `ok` exige: cadena continua desde 1, hashes válidos, ninguna fila sin sellar, y (si se da) el ancla presente en su posición.
    Con clave configurada, una fila sellada SIN clave (`key_id='none'`) o con una clave que no conocemos es una ROTURA (un atacante
    podría insertar una fila "firmada" con otra clave y quedaría sin comprobar). Excepciones declaradas por el operador: claves
    anteriores de una rotación (AUDIT_CHAIN_PREVIOUS_KEYS) y, CON TOPE de posición, claves perdidas (AUDIT_CHAIN_LOST_KEY_IDS=id:pos) y
    el histórico sin clave (AUDIT_CHAIN_ACCEPT_UNKEYED=pos). Sin ninguna clave configurada (desarrollo) lo que no se puede recalcular
    solo se cuenta en `unverifiable`. `hints` = por cada clave desconocida (o 'none'), la primera posición y el final de su primer tramo
    CONTIGUO: ayuda a fijar el tope, que el operador DEBE confirmar con sus anclas (un tope mayor que lo legítimo reabre el hueco).
    """
    key = get_key()
    kid = key_id(key)
    keys = {kid: key} if key else {}
    keys.update(previous_keys())
    lost = lost_key_ids()
    unkeyed_cap = accept_unkeyed_cap()
    runs: Dict[str, Dict[str, Any]] = {}

    def track(k, pos):
        run = runs.setdefault(k, {'first': pos, 'last': pos, 'open': True})
        if run['last'] != pos:
            if run['open'] and pos == run['last'] + 1:
                run['last'] = pos
            else:
                run['open'] = False
    broken = None
    checked = unverifiable = 0
    exp_pos, prev_hash, last_pos = 1, GENESIS, 0
    anchor_found = None
    anchor_pos = anchor_hash = None
    if anchor:
        anchor_pos, anchor_hash = parse_anchor(anchor)

    def rotura(pos, rid, reason):
        nonlocal broken
        if broken is None:
            broken = {'pos': pos, 'id': rid, 'reason': reason}

    after = 0
    while True:
        rows = db.session.execute(text(
            'SELECT id, chain_pos, prev_hash, entry_hash, key_id, algo, username, action, resource_type, resource_id, details, '
            'ip_address, user_agent, request_id, success, created_at FROM audit_events '
            'WHERE chain_pos IS NOT NULL AND chain_pos > :a ORDER BY chain_pos LIMIT :n'), {'a': after, 'n': batch}).all()
        if not rows:
            break
        for r in rows:
            after = r.chain_pos
            checked += 1
            if r.chain_pos != exp_pos:
                rotura(exp_pos, None, f'falta(n) el/los eslabón(es) {exp_pos}..{r.chain_pos - 1} (borrado o inicio recortado)')
                exp_pos = r.chain_pos                   # sigue comprobando el resto a partir de aquí
            if r.prev_hash != prev_hash:
                rotura(r.chain_pos, r.id, 'el enlace con el eslabón anterior no cuadra (fila borrada, insertada o reordenada)')
            if r.algo not in ALGOS:
                rotura(r.chain_pos, r.id, f'algoritmo desconocido: {r.algo}')
                row_key, verificable = None, False
            elif r.key_id == 'none':
                dentro = unkeyed_cap is not None and r.chain_pos <= unkeyed_cap
                row_key, verificable = None, bool(not key or dentro)
                if key:
                    track('none', r.chain_pos)
                if key and not dentro:
                    rotura(r.chain_pos, r.id, 'fila sellada SIN clave en una cadena con clave (forjable). Si es histórico previo a la clave: '
                                              'AUDIT_CHAIN_ACCEPT_UNKEYED=<ultima posicion sin clave> (ver `flask audit verify`)')
            elif r.key_id in keys:
                row_key, verificable = keys[r.key_id], True
            elif r.key_id in lost:
                row_key, verificable = None, False
                track(r.key_id, r.chain_pos)
                if r.chain_pos <= lost[r.key_id]:
                    unverifiable += 1                   # clave perdida DECLARADA y dentro de su tope: solo se comprueba el enlace y la posición
                else:
                    rotura(r.chain_pos, r.id, f'fila con la clave declarada perdida ({r.key_id}) POR ENCIMA de su tope ({lost[r.key_id]}): '
                                              'ya no se pueden sellar filas con esa clave (¿inserción posterior?)')
            else:
                row_key, verificable = None, False
                if key:
                    track(r.key_id, r.chain_pos)
                    rotura(r.chain_pos, r.id, f'sellada con una clave desconocida ({r.key_id}): ¿rotación? declárala en AUDIT_CHAIN_PREVIOUS_KEYS '
                                              '(o, si se PERDIÓ, AUDIT_CHAIN_LOST_KEY_IDS=<key_id>:<ultima posicion>; ver `flask audit verify`)')
                else:
                    unverifiable += 1                   # sin clave configurada no se puede juzgar
            if verificable and not hmac.compare_digest(compute_hash(row_key, r.chain_pos, r.prev_hash, _fields_from_row(r)), r.entry_hash or ''):
                rotura(r.chain_pos, r.id, 'el contenido de la fila no coincide con su sello (editada)')
            if anchor_pos is not None and r.chain_pos == anchor_pos:
                anchor_found = r.entry_hash
            prev_hash, exp_pos, last_pos = r.entry_hash, r.chain_pos + 1, r.chain_pos
    unsealed = db.session.execute(text('SELECT count(*) FROM audit_events WHERE chain_pos IS NULL')).scalar()
    if unsealed:
        rotura(None, None, f'{unsealed} fila(s) SIN sellar (anteriores a la cadena: `flask audit seal-legacy`; o insertadas sin pasar por la app)')
    anchor_res = None
    if anchor_pos is not None:
        if last_pos < anchor_pos:
            anchor_res = f'FALLA: la cadena termina en {last_pos}, antes del ancla ({anchor_pos}): se borraron las últimas filas'
            rotura(anchor_pos, None, anchor_res)
        elif anchor_found != anchor_hash:
            anchor_res = f'FALLA: el eslabón {anchor_pos} no tiene el hash del ancla'
            rotura(anchor_pos, None, anchor_res)
        else:
            anchor_res = 'ok'
    return {'ok': broken is None, 'checked': checked, 'broken': broken, 'unverifiable': unverifiable, 'unsealed': unsealed,
            'tail': tail(), 'key_id': kid, 'anchor': anchor_res,
            'hints': {k: {'first': v['first'], 'last_contiguous': v['last']} for k, v in runs.items()}}


def seal_legacy() -> int:
    """Sella las filas anteriores a la cadena (por orden de id) a continuación del último eslabón. Devuelve cuántas selló."""
    key = get_key()
    kid = key_id(key)
    n = 0
    try:
        pos, prev = _lock_and_tail(db.session)
        rows = db.session.execute(text(
            'SELECT id, username, action, resource_type, resource_id, details, ip_address, user_agent, request_id, success, created_at '
            'FROM audit_events WHERE chain_pos IS NULL ORDER BY id')).all()
        for r in rows:
            pos += 1
            h = compute_hash(key, pos, prev, _fields_from_row(r))
            db.session.execute(text('UPDATE audit_events SET chain_pos=:p, prev_hash=:ph, entry_hash=:h, key_id=:k, algo=:a WHERE id=:i'),
                               {'p': pos, 'ph': prev, 'h': h, 'k': kid, 'a': ALGO_LEGACY, 'i': r.id})
            prev = h
            n += 1
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise
    return n


# ============================================================================ ancla externa (Telegram)

_next_attempt: Optional[datetime] = None


def format_anchor_message(result: Dict[str, Any]) -> str:
    from app.services.telegram_client import escape as e
    t = result.get('tail') or {}
    if result['ok']:
        estado = '✅ cadena íntegra'
    else:
        b = result.get('broken') or {}
        estado = f"🚨 <b>CADENA ROTA</b>: {e(b.get('reason'))}" + (f" (eslabón {b['pos']})" if b.get('pos') else '')
    return '\n'.join([
        '<b>SOC Agent: ancla de la auditoría</b>', estado,
        f"Eslabones comprobados: {result['checked']}",
        f"Ancla: <code>{t.get('pos')}:{t.get('hash')}</code>" if t else 'Sin eslabones todavía',
        'Guárdala: <code>flask audit verify --anchor POS:HASH</code> detecta que borren las últimas filas.'])


def maybe_anchor(now: Optional[datetime] = None) -> Dict[str, Any]:
    """Cada ANCHOR_EVERY verifica la cadena y publica su extremo por Telegram (el testigo fuera de la BD). Nunca lanza."""
    global _next_attempt
    from app.services import telegram_client
    if not telegram_client.configured():
        return {'status': 'disabled'}
    now = now or utcnow()
    if _next_attempt is not None and now < _next_attempt:
        return {'status': 'backoff'}
    try:
        ultimo = db.session.execute(text('SELECT max(created_at) FROM audit_events WHERE action = :a'), {'a': ANCHOR_ACTION}).scalar()
        if ultimo is not None and now - ultimo < ANCHOR_EVERY:
            return {'status': 'idle'}
        res = verify_chain()
        if res['tail'] is None:
            return {'status': 'idle'}
        out = telegram_client.send_to_chats(format_anchor_message(res))
        if not out['sent'] or out['transient']:
            _next_attempt = now + RETRY_BACKOFF
            return {'status': 'retry', 'ok': res['ok']}
        AuditEvent.log(ANCHOR_ACTION, resource_type='audit', success=res['ok'], _commit=True,
                       details={'pos': res['tail']['pos'], 'hash': res['tail']['hash'], 'ok': res['ok'], 'checked': res['checked']})
        _next_attempt = None
        return {'status': 'sent', 'ok': res['ok']}
    except Exception as e:
        db.session.rollback()
        logger.error('audit_chain.maybe_anchor: %s', telegram_client.redact(e))
        _next_attempt = now + RETRY_BACKOFF
        return {'status': 'retry', 'error': telegram_client.redact(e)}


def reset_backoff() -> None:
    """Solo para tests."""
    global _next_attempt, _warned
    _next_attempt = None
    _warned = False
