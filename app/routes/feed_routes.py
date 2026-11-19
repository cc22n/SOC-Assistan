"""
Feeds proactivos (WP6): CVEs que llegan solos, filtrados por el stack declarado.

  GET    /api/v2/feeds/items            ?relevant=1 (por defecto) | 0 = todos; ?risk=ALTO (mínimo); ?days=30; ?limit&offset
  GET    /api/v2/feeds/status           salud de cada fuente (última ejecución, retraso) y contadores
  GET    /api/v2/feeds/stack            el stack declarado
  POST   /api/v2/feeds/stack            añadir una tecnología (senior_analyst+: afecta a lo que ve TODA la organización)
  DELETE /api/v2/feeds/stack/<id>       quitarla (senior_analyst+)
  GET    /feeds                         página

El stack es GLOBAL (de la organización). Los CVE son información pública: los ven todos los roles. Las ejecuciones las lanza el
servicio `feeds` (`flask feeds daemon`), no esta API: una petición web de ~15 s que además podría duplicarse con el daemon no es
un buen sitio para ello.
"""
from datetime import timedelta

from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user, login_required
from sqlalchemy.exc import IntegrityError

from app import db, limiter
from app.models.audit import AuditEvent
from app.models.feed import FeedItem, FeedRun, TechStackEntry
from app.services import feed_runner
from app.services.feed_matching import entry_is_valid
from app.utils.auth import require_role
from app.utils.responses import safe_error_response
from app.utils.time_utils import utcnow

bp = Blueprint('feeds_api', __name__, url_prefix='/api/v2/feeds')
pages_bp = Blueprint('feeds_pages', __name__)

MAX_STACK = 200
RISK_ORDER = ['LIMPIO', 'BAJO', 'MEDIO', 'ALTO', 'CRÍTICO']


def _clean(v):
    v = (v or '').strip() if isinstance(v, str) else None
    return v or None


@bp.route('/items', methods=['GET'])
@login_required
def list_items():
    try:
        relevant = request.args.get('relevant', '1') != '0'
        days = min(max(request.args.get('days', 30, type=int), 1), 365)
        limit = min(max(request.args.get('limit', 50, type=int), 1), 200)
        offset = max(request.args.get('offset', 0, type=int), 0)
        q = FeedItem.query.filter(FeedItem.first_seen_at >= utcnow() - timedelta(days=days))
        if relevant:
            q = q.filter(FeedItem.is_relevant.is_(True))
        risk = request.args.get('risk')
        if risk:
            if risk not in RISK_ORDER:
                return jsonify({'error': f'risk debe ser uno de {RISK_ORDER}'}), 400
            q = q.filter(FeedItem.risk_level.in_(RISK_ORDER[RISK_ORDER.index(risk):]))
        total = q.count()
        rows = q.order_by(FeedItem.priority_score.desc(), FeedItem.published_at.desc().nullslast(),
                          FeedItem.id.desc()).offset(offset).limit(limit).all()
        stack = {e.id: e.label() for e in TechStackEntry.query.all()}
        items = []
        for r in rows:
            d = r.to_dict()
            d['matched_labels'] = [stack[i] for i in d['matched_entries'] if i in stack]
            items.append(d)
        return jsonify({'success': True, 'total': total, 'count': len(items), 'items': items}), 200
    except Exception as e:
        return safe_error_response(e, "List feed items error")


@bp.route('/status', methods=['GET'])
@login_required
def status():
    try:
        now = utcnow()
        sources = []
        for name, spec in feed_runner.SOURCES.items():
            last = FeedRun.query.filter_by(source=name).order_by(FeedRun.started_at.desc()).first()
            ok = feed_runner.last_ok_run(name)
            sources.append({
                'source': name, 'interval_hours': spec.interval.total_seconds() / 3600,
                'last_run': last.to_dict() if last else None,
                'last_ok': ok.started_at.isoformat() if ok else None,
                'lag_minutes': int((now - ok.started_at).total_seconds() // 60) if ok else None,
                # "vencida" desde hace más de 2 intervalos = el servicio `feeds` probablemente no está corriendo
                'stale': ok is None or (now - ok.started_at) > spec.interval * 2,
            })
        week = now - timedelta(days=7)
        return jsonify({
            'success': True, 'sources': sources, 'stack_size': TechStackEntry.query.count(),
            'items_total': FeedItem.query.count(),
            'relevant_total': FeedItem.query.filter_by(is_relevant=True).count(),
            'relevant_last_7d': FeedItem.query.filter(FeedItem.is_relevant.is_(True), FeedItem.first_seen_at >= week).count(),
        }), 200
    except Exception as e:
        return safe_error_response(e, "Feed status error")


@bp.route('/stack', methods=['GET'])
@login_required
def list_stack():
    return jsonify({'success': True, 'entries': [e.to_dict() for e in TechStackEntry.query.order_by(TechStackEntry.id)]}), 200


@bp.route('/stack', methods=['POST'])
@login_required
@require_role('senior_analyst')
@limiter.limit("60 per hour")
def add_stack_entry():
    data = request.get_json(silent=True)
    data = data if isinstance(data, dict) else {}
    vendor, product = _clean(data.get('vendor')), _clean(data.get('product'))
    note = (data.get('note') or '').strip() if isinstance(data.get('note'), str) else ''
    if not entry_is_valid(vendor, product):
        return jsonify({'error': 'Indica un vendor o un producto (con algún nombre significativo)'}), 400
    if any(v and len(v) > 120 for v in (vendor, product)) or len(note) > 300:
        return jsonify({'error': 'vendor/producto máx. 120 caracteres, nota máx. 300'}), 400
    try:
        if TechStackEntry.query.count() >= MAX_STACK:
            return jsonify({'error': f'Máximo {MAX_STACK} entradas'}), 409
        e = TechStackEntry(vendor=vendor, product=product, note=note, created_by=current_user.id)
        db.session.add(e)
        db.session.flush()
        AuditEvent.log('feed_stack_added', resource_type='feed_stack', resource_id=e.id,
                       details={'vendor': vendor, 'product': product})
        db.session.commit()
        rel = feed_runner.recompute_relevance()
        return jsonify({'success': True, 'entry': e.to_dict(), 'relevance': rel}), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Esa tecnología ya está en el stack'}), 409
    except Exception as e:
        db.session.rollback()
        return safe_error_response(e, "Add stack entry error")


@bp.route('/stack/<int:entry_id>', methods=['DELETE'])
@login_required
@require_role('senior_analyst')
@limiter.limit("60 per hour")
def delete_stack_entry(entry_id):
    e = db.session.get(TechStackEntry, entry_id)
    if e is None:
        return jsonify({'error': 'Entrada no encontrada'}), 404
    try:
        detalles = {'vendor': e.vendor, 'product': e.product}
        db.session.delete(e)
        db.session.flush()
        AuditEvent.log('feed_stack_removed', resource_type='feed_stack', resource_id=entry_id, details=detalles)
        db.session.commit()
        return jsonify({'success': True, 'relevance': feed_runner.recompute_relevance()}), 200
    except Exception as ex:
        db.session.rollback()
        return safe_error_response(ex, "Delete stack entry error")


@pages_bp.route('/feeds')
@login_required
def feeds_page():
    return render_template('feeds.html')
