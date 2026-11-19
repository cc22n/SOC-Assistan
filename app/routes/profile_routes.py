"""
Perfiles de investigación (WP2 de PLAN-FUSION): consultas repetibles definidas por el analista.

  GET    /api/v2/profiles                 -> perfiles visibles (del sistema + propios; admin: todos). ?ioc_type=ip
  GET    /api/v2/profiles/catalog         -> por tipo de IOC, las APIs que se pueden elegir (derivado del código)
  POST   /api/v2/profiles                 -> crear (analyst+)
  GET    /api/v2/profiles/<id>
  PUT    /api/v2/profiles/<id>            -> editar (dueño o admin; los del sistema son inmutables)
  DELETE /api/v2/profiles/<id>            -> borrar (dueño o admin; los del sistema son inmutables)
  GET    /profiles                        -> página de gestión

Ejecutar un perfil: POST /api/v2/analyze/enhanced con "profile_id" (ver api_v2_routes.py).
Un perfil ajeno responde 404 (no 403): no se revela que existe.
"""
from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user, login_required
from sqlalchemy.exc import IntegrityError

from app import db, limiter
from app.models.audit import AuditEvent
from app.models.profile import InvestigationProfile
from app.services.profile_service import (
    IOC_TYPES, MAX_PROFILES_PER_USER, compatible_apis, validate_profile_fields,
)
from app.utils.auth import require_role
from app.utils.responses import safe_error_response

bp = Blueprint('profiles_api', __name__, url_prefix='/api/v2/profiles')
pages_bp = Blueprint('profiles_pages', __name__)


def _visible_query():
    q = InvestigationProfile.query
    if current_user.role != 'admin':
        q = q.filter(db.or_(InvestigationProfile.is_system.is_(True),
                            InvestigationProfile.owner_id == current_user.id))
    return q


def _get_visible_or_404(profile_id):
    p = db.session.get(InvestigationProfile, profile_id)
    if p is None or not p.is_visible_to(current_user):
        return None, (jsonify({'error': 'Perfil no encontrado'}), 404)
    return p, None


def _body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


@bp.route('', methods=['GET'])
@login_required
def list_profiles():
    try:
        q = _visible_query()
        ioc_type = request.args.get('ioc_type')
        if ioc_type:
            if ioc_type not in IOC_TYPES:
                return jsonify({'error': f'ioc_type debe ser uno de {list(IOC_TYPES)}'}), 400
            q = q.filter(InvestigationProfile.ioc_type == ioc_type)
        rows = q.order_by(InvestigationProfile.is_system.desc(), InvestigationProfile.ioc_type,
                          db.func.lower(InvestigationProfile.name)).all()
        return jsonify({'success': True, 'count': len(rows), 'profiles': [p.to_dict() for p in rows]}), 200
    except Exception as e:
        return safe_error_response(e, "List profiles error")


@bp.route('/catalog', methods=['GET'])
@login_required
def catalog():
    """APIs elegibles por tipo de IOC (para el formulario). Derivado de IOCAnalysis y _is_api_compatible."""
    try:
        return jsonify({'success': True, 'max_apis': InvestigationProfile.MAX_APIS,
                        'catalog': {t: compatible_apis(t) for t in IOC_TYPES}}), 200
    except Exception as e:
        return safe_error_response(e, "Profile catalog error")


@bp.route('', methods=['POST'])
@login_required
@require_role('analyst')   # viewer = solo lectura
@limiter.limit("30 per hour")
def create_profile():
    data = _body()
    clean, errors = validate_profile_fields(data.get('name'), data.get('description'), data.get('ioc_type'),
                                            data.get('apis'), data.get('llm_synthesis', True))
    if errors:
        return jsonify({'error': 'Datos inválidos', 'details': errors}), 400
    try:
        if InvestigationProfile.query.filter_by(owner_id=current_user.id).count() >= MAX_PROFILES_PER_USER:
            return jsonify({'error': f'Máximo {MAX_PROFILES_PER_USER} perfiles por usuario'}), 409
        p = InvestigationProfile(owner_id=current_user.id, is_system=False, **clean)
        db.session.add(p)
        db.session.flush()
        AuditEvent.log('profile_created', resource_type='profile', resource_id=p.id,
                       details={'name': p.name, 'ioc_type': p.ioc_type, 'apis': p.apis}, _commit=True)
        return jsonify({'success': True, 'profile': p.to_dict()}), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Ya tienes un perfil con ese nombre'}), 409
    except Exception as e:
        db.session.rollback()
        return safe_error_response(e, "Create profile error")


@bp.route('/<int:profile_id>', methods=['GET'])
@login_required
def get_profile(profile_id):
    p, err = _get_visible_or_404(profile_id)
    if err:
        return err
    return jsonify({'success': True, 'profile': p.to_dict()}), 200


@bp.route('/<int:profile_id>', methods=['PUT'])
@login_required
@require_role('analyst')
@limiter.limit("60 per hour")
def update_profile(profile_id):
    p, err = _get_visible_or_404(profile_id)
    if err:
        return err
    if not p.is_editable_by(current_user):
        return jsonify({'error': 'Los perfiles del sistema no se pueden modificar' if p.is_system
                        else 'No autorizado'}), 403
    data = _body()
    # PUT parcial: lo no enviado conserva su valor; el tipo de IOC no se cambia (invalidaría las APIs elegidas)
    if 'ioc_type' in data and data['ioc_type'] != p.ioc_type:
        return jsonify({'error': 'ioc_type no se puede cambiar; crea otro perfil'}), 400
    clean, errors = validate_profile_fields(
        data.get('name', p.name), data.get('description', p.description), p.ioc_type,
        data.get('apis', p.apis), data.get('llm_synthesis', p.llm_synthesis))
    if errors:
        return jsonify({'error': 'Datos inválidos', 'details': errors}), 400
    try:
        antes = {'name': p.name, 'apis': list(p.apis)}
        p.name, p.description, p.apis, p.llm_synthesis = (
            clean['name'], clean['description'], clean['apis'], clean['llm_synthesis'])
        AuditEvent.log('profile_updated', resource_type='profile', resource_id=p.id,
                       details={'antes': antes, 'despues': {'name': p.name, 'apis': p.apis}}, _commit=True)
        return jsonify({'success': True, 'profile': p.to_dict()}), 200
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Ya tienes un perfil con ese nombre'}), 409
    except Exception as e:
        db.session.rollback()
        return safe_error_response(e, "Update profile error")


@bp.route('/<int:profile_id>', methods=['DELETE'])
@login_required
@require_role('analyst')
@limiter.limit("60 per hour")
def delete_profile(profile_id):
    p, err = _get_visible_or_404(profile_id)
    if err:
        return err
    if not p.is_editable_by(current_user):
        return jsonify({'error': 'Los perfiles del sistema no se pueden borrar' if p.is_system
                        else 'No autorizado'}), 403
    try:
        # los análisis hechos con él conservan su resultado (profile_id pasa a NULL por ON DELETE SET NULL)
        detalles = {'name': p.name, 'ioc_type': p.ioc_type}
        db.session.delete(p)
        db.session.flush()
        AuditEvent.log('profile_deleted', resource_type='profile', resource_id=profile_id,
                       details=detalles, _commit=True)
        return jsonify({'success': True}), 200
    except Exception as e:
        db.session.rollback()
        return safe_error_response(e, "Delete profile error")


@pages_bp.route('/profiles')
@login_required
def profiles_page():
    return render_template('profiles.html')
