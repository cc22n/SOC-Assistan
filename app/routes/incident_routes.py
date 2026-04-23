"""
Incident Routes - SOC Agent v3.1
CRUD completo para gestion de incidentes de seguridad

Endpoints:
- POST   /api/v2/incidents              - Crear incidente
- GET    /api/v2/incidents              - Listar incidentes (con filtros)
- GET    /api/v2/incidents/{id}         - Detalle de incidente
- PUT    /api/v2/incidents/{id}         - Actualizar incidente
- PUT    /api/v2/incidents/{id}/status  - Cambiar estado
- POST   /api/v2/incidents/{id}/notes   - Agregar nota al timeline
- POST   /api/v2/incidents/{id}/iocs    - Vincular IOC(s)
- DELETE /api/v2/incidents/{id}/iocs/{ioc_id} - Desvincular IOC
- GET    /api/v2/incidents/{id}/timeline - Timeline completo (notas + chat)
- GET    /api/v2/incidents/stats        - Estadisticas de incidentes
"""
from typing import Any, Tuple

from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from datetime import datetime
from sqlalchemy import desc
from app import db
from app.models.ioc import Incident, IncidentIOC, IOC, IOCAnalysis, User
import logging

logger = logging.getLogger(__name__)

bp = Blueprint('incidents_api', __name__, url_prefix='/api/v2/incidents')


def _safe_error(e: Exception, context: str = "") -> Tuple[Any, int]:
    """Retorna error sin exponer detalles internos (VULN-02 fix)"""
    logger.error(f"{context}: {e}", exc_info=True)
    from flask import current_app
    if current_app.debug:
        return jsonify({'error': str(e)}), 500
    return jsonify({'error': 'Internal server error'}), 500


def _check_incident_access(incident: Incident) -> bool:
    """Verifica que el usuario tenga acceso al incidente (VULN-01 fix)"""
    if current_user.role == 'admin':
        return True
    if incident.created_by == current_user.id:
        return True
    if incident.assigned_to == current_user.id:
        return True
    # Registrar intento de acceso no autorizado
    from app.models.audit import AuditEvent
    AuditEvent.log(
        'unauthorized_access',
        resource_type='incident',
        resource_id=incident.id,
        success=False,
        details={'ticket_id': incident.ticket_id, 'reason': 'IDOR attempt'},
        _commit=True,
    )
    return False


# =============================================================================
# CREAR INCIDENTE
# =============================================================================

@bp.route('', methods=['POST'])
@login_required
def create_incident():
    """
    Crea un nuevo incidente.

    Body JSON:
    {
        "title": "Amenaza critica detectada",
        "description": "Descripcion detallada...",
        "severity": "P1",               // P1, P2, P3, P4
        "assigned_to": 1,               // user_id (opcional)
        "session_id": 5,                // vincular con sesion (opcional)
        "analysis_id": 12,              // vincular con analisis (opcional)
        "ioc_ids": [1, 2, 3],           // IOCs a vincular (opcional)
        "primary_ioc_id": 1             // IOC principal (opcional)
    }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON requerido'}), 400

        title = data.get('title', '').strip()
        if not title:
            return jsonify({'error': 'Titulo requerido'}), 400

        severity = data.get('severity', 'P3')
        if severity not in ['P1', 'P2', 'P3', 'P4']:
            return jsonify({'error': 'Severidad invalida (P1-P4)'}), 400

        # Crear incidente
        incident = Incident(
            ticket_id=Incident.generate_ticket_id(),
            title=title,
            description=data.get('description', ''),
            severity=severity,
            status='open',
            assigned_to=data.get('assigned_to'),
            created_by=current_user.id,
            analysis_id=data.get('analysis_id'),
            session_id=data.get('session_id'),
        )

        # Timeline: evento de creacion
        incident.add_timeline_event(
            'created',
            f'Incidente creado por {current_user.username}',
            user=current_user.username
        )

        db.session.add(incident)
        db.session.flush()  # Para obtener el ID

        # Vincular IOCs
        ioc_ids = data.get('ioc_ids', [])
        primary_ioc_id = data.get('primary_ioc_id')

        if ioc_ids:
            # Batch fetch IOCs and latest analysis IDs to avoid N+1 queries
            iocs_map = {
                ioc.id: ioc
                for ioc in db.session.query(IOC).filter(IOC.id.in_(ioc_ids)).all()
            }
            from sqlalchemy import func
            latest_analyses = dict(
                db.session.query(IOCAnalysis.ioc_id, func.max(IOCAnalysis.id))
                .filter(IOCAnalysis.ioc_id.in_(ioc_ids))
                .group_by(IOCAnalysis.ioc_id)
                .all()
            )

            for ioc_id in ioc_ids:
                ioc = iocs_map.get(ioc_id)
                if ioc:
                    role = 'primary' if ioc_id == primary_ioc_id else 'related'
                    link = IncidentIOC(
                        incident_id=incident.id,
                        ioc_id=ioc_id,
                        analysis_id=latest_analyses.get(ioc_id),
                        role=role
                    )
                    db.session.add(link)
                    incident.add_timeline_event(
                        'ioc_linked',
                        f'IOC vinculado: {ioc.value} ({role})',
                        user=current_user.username
                    )

        db.session.commit()

        logger.info(f"Incident {incident.ticket_id} created by {current_user.username}")

        return jsonify({
            'success': True,
            'incident': incident.to_dict(include_iocs=True)
        }), 201

    except Exception as e:
        db.session.rollback()
        return _safe_error(e, "Error creating incident")


# =============================================================================
# LISTAR INCIDENTES
# =============================================================================

@bp.route('', methods=['GET'])
@login_required
def list_incidents():
    """
    Lista incidentes con filtros y paginación.

    Query params:
    - status: open, investigating, resolved, closed (puede ser CSV)
    - severity: P1, P2, P3, P4
    - assigned_to: user_id
    - my_only: true/false
    - page: int (default 1)
    - per_page: int (default 20, máx 100)
    """
    try:
        query = Incident.query

        # Non-admin users can only see their own incidents (created_by or assigned_to).
        # Admins see all incidents; my_only=true is the default for non-admins.
        if current_user.role != 'admin':
            query = query.filter(
                (Incident.created_by == current_user.id) |
                (Incident.assigned_to == current_user.id)
            )
        else:
            my_only = request.args.get('my_only', 'false').lower() == 'true'
            if my_only:
                query = query.filter(
                    (Incident.created_by == current_user.id) |
                    (Incident.assigned_to == current_user.id)
                )

        # Filtro por status (acepta CSV: "open,investigating")
        status = request.args.get('status')
        if status:
            statuses = [s.strip() for s in status.split(',')]
            query = query.filter(Incident.status.in_(statuses))

        severity = request.args.get('severity')
        if severity:
            query = query.filter_by(severity=severity)

        assigned_to = request.args.get('assigned_to', type=int)
        if assigned_to:
            query = query.filter_by(assigned_to=assigned_to)

        page = max(1, request.args.get('page', 1, type=int))
        per_page = min(100, max(1, request.args.get('per_page', 20, type=int)))

        total = query.count()
        incidents = (
            query.order_by(desc(Incident.created_at))
            .offset((page - 1) * per_page)
            .limit(per_page)
            .all()
        )

        return jsonify({
            'success': True,
            'incidents': [i.to_dict() for i in incidents],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page,
            }
        }), 200

    except Exception as e:
        logger.error(f"Error listing incidents: {e}")
        return _safe_error(e, "Error listing incidents")


# =============================================================================
# DETALLE DE INCIDENTE
# =============================================================================

@bp.route('/<int:incident_id>', methods=['GET'])
@login_required
def get_incident(incident_id):
    """Obtiene detalle completo de un incidente"""
    try:
        incident = db.session.get(Incident, incident_id)
        if not incident:
            return jsonify({'error': 'Incidente no encontrado'}), 404

        if not _check_incident_access(incident):
            return jsonify({'error': 'No autorizado'}), 403

        return jsonify({
            'success': True,
            'incident': incident.to_dict(include_iocs=True)
        }), 200

    except Exception as e:
        return _safe_error(e, "Error getting incident")


# =============================================================================
# ACTUALIZAR INCIDENTE
# =============================================================================

@bp.route('/<int:incident_id>', methods=['PUT'])
@login_required
def update_incident(incident_id):
    """
    Actualiza campos de un incidente.

    Body JSON:
    {
        "title": "Nuevo titulo",
        "description": "Nueva descripcion",
        "severity": "P2",
        "assigned_to": 2,
        "notes": "Notas adicionales"
    }
    """
    try:
        incident = db.session.get(Incident, incident_id)
        if not incident:
            return jsonify({'error': 'Incidente no encontrado'}), 404

        if not _check_incident_access(incident):
            return jsonify({'error': 'No autorizado'}), 403

        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON requerido'}), 400

        changes = []

        if 'title' in data:
            old = incident.title
            incident.title = data['title']
            changes.append(f'Titulo: "{old}" -> "{data["title"]}"')

        if 'description' in data:
            incident.description = data['description']
            changes.append('Descripcion actualizada')

        if 'severity' in data and data['severity'] in ['P1', 'P2', 'P3', 'P4']:
            old = incident.severity
            incident.severity = data['severity']
            changes.append(f'Severidad: {old} -> {data["severity"]}')

        if 'assigned_to' in data:
            old_user = incident.assignee.username if incident.assignee else 'nadie'
            incident.assigned_to = data['assigned_to']
            new_user = db.session.get(User, data['assigned_to'])
            new_name = new_user.username if new_user else 'nadie'
            changes.append(f'Asignado: {old_user} -> {new_name}')

        if 'notes' in data:
            incident.notes = data['notes']

        if changes:
            incident.add_timeline_event(
                'updated',
                '; '.join(changes),
                user=current_user.username
            )

        db.session.commit()

        return jsonify({
            'success': True,
            'incident': incident.to_dict(include_iocs=True)
        }), 200

    except Exception as e:
        db.session.rollback()
        return _safe_error(e, "Error updating incident")


# =============================================================================
# CAMBIAR ESTADO
# =============================================================================

@bp.route('/<int:incident_id>/status', methods=['PUT'])
@login_required
def change_status(incident_id):
    """
    Cambia el estado de un incidente.

    Body JSON:
    {
        "status": "investigating",     // open, investigating, resolved, closed
        "reason": "Iniciando analisis" // opcional
    }
    """
    try:
        incident = db.session.get(Incident, incident_id)
        if not incident:
            return jsonify({'error': 'Incidente no encontrado'}), 404

        if not _check_incident_access(incident):
            return jsonify({'error': 'No autorizado'}), 403

        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON requerido'}), 400

        new_status = data.get('status', '').strip()
        reason = data.get('reason', '')

        valid_statuses = ['open', 'investigating', 'resolved', 'closed']
        if new_status not in valid_statuses:
            return jsonify({'error': f'Estado invalido. Validos: {valid_statuses}'}), 400

        old_status = incident.status
        incident.status = new_status

        if new_status == 'resolved':
            incident.resolved_at = datetime.utcnow()

        description = f'Estado: {old_status} -> {new_status}'
        if reason:
            description += f' ({reason})'

        incident.add_timeline_event(
            'status_changed',
            description,
            user=current_user.username
        )

        db.session.commit()

        return jsonify({
            'success': True,
            'incident': incident.to_dict()
        }), 200

    except Exception as e:
        db.session.rollback()
        return _safe_error(e, "Error changing status")


# =============================================================================
# AGREGAR NOTA AL TIMELINE
# =============================================================================

@bp.route('/<int:incident_id>/notes', methods=['POST'])
@login_required
def add_note(incident_id):
    """
    Agrega una nota al timeline del incidente.

    Body JSON:
    {
        "content": "Se confirmo que el C2 esta activo...",
        "type": "note"  // note, finding, action (default: note)
    }
    """
    try:
        incident = db.session.get(Incident, incident_id)
        if not incident:
            return jsonify({'error': 'Incidente no encontrado'}), 404

        if not _check_incident_access(incident):
            return jsonify({'error': 'No autorizado'}), 403

        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON requerido'}), 400

        content = data.get('content', '').strip()
        if not content:
            return jsonify({'error': 'Contenido requerido'}), 400

        event_type = data.get('type', 'note')
        if event_type not in ['note', 'finding', 'action']:
            event_type = 'note'

        incident.add_timeline_event(
            event_type,
            content,
            user=current_user.username
        )

        db.session.commit()

        return jsonify({
            'success': True,
            'timeline': incident.timeline
        }), 200

    except Exception as e:
        db.session.rollback()
        return _safe_error(e, "Error adding note")


# =============================================================================
# VINCULAR IOC(s)
# =============================================================================

@bp.route('/<int:incident_id>/iocs', methods=['POST'])
@login_required
def link_iocs(incident_id):
    """
    Vincula IOC(s) a un incidente.

    Body JSON:
    {
        "ioc_ids": [1, 2, 3],
        "role": "related",        // primary, related, context
        "notes": "IOC encontrado en logs"
    }
    """
    try:
        incident = db.session.get(Incident, incident_id)
        if not incident:
            return jsonify({'error': 'Incidente no encontrado'}), 404

        if not _check_incident_access(incident):
            return jsonify({'error': 'No autorizado'}), 403

        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON requerido'}), 400

        ioc_ids = data.get('ioc_ids', [])
        role = data.get('role', 'related')
        notes = data.get('notes')

        if not ioc_ids:
            return jsonify({'success': True, 'linked': [], 'incident': incident.to_dict(include_iocs=True)}), 200

        # Batch fetch IOCs and existing links to avoid N+1 queries
        iocs_by_id = {
            ioc.id: ioc
            for ioc in db.session.query(IOC).filter(IOC.id.in_(ioc_ids)).all()
        }
        existing_links = {
            row.ioc_id
            for row in IncidentIOC.query.filter_by(incident_id=incident_id)
                .filter(IncidentIOC.ioc_id.in_(ioc_ids)).all()
        }

        # Latest analysis per IOC in one query
        from sqlalchemy import func
        latest_analysis_ids = dict(
            db.session.query(IOCAnalysis.ioc_id, func.max(IOCAnalysis.id))
            .filter(IOCAnalysis.ioc_id.in_(ioc_ids))
            .group_by(IOCAnalysis.ioc_id)
            .all()
        )

        linked = []
        for ioc_id in ioc_ids:
            ioc = iocs_by_id.get(ioc_id)
            if not ioc or ioc_id in existing_links:
                continue

            analysis_id = latest_analysis_ids.get(ioc_id)

            link = IncidentIOC(
                incident_id=incident_id,
                ioc_id=ioc_id,
                analysis_id=analysis_id,
                role=role,
                notes=notes
            )
            db.session.add(link)
            linked.append(ioc.value)

            incident.add_timeline_event(
                'ioc_linked',
                f'IOC vinculado: {ioc.value} ({role})',
                user=current_user.username
            )

        db.session.commit()

        return jsonify({
            'success': True,
            'linked': linked,
            'incident': incident.to_dict(include_iocs=True)
        }), 200

    except Exception as e:
        db.session.rollback()
        return _safe_error(e, "Error linking IOCs")


# =============================================================================
# DESVINCULAR IOC
# =============================================================================

@bp.route('/<int:incident_id>/iocs/<int:ioc_id>', methods=['DELETE'])
@login_required
def unlink_ioc(incident_id, ioc_id):
    """Desvincula un IOC de un incidente"""
    try:
        link = IncidentIOC.query.filter_by(
            incident_id=incident_id, ioc_id=ioc_id
        ).first()

        if not link:
            return jsonify({'error': 'Vinculo no encontrado'}), 404

        incident = db.session.get(Incident, incident_id)
        if not incident:
            return jsonify({'error': 'Incidente no encontrado'}), 404

        if not _check_incident_access(incident):
            return jsonify({'error': 'No autorizado'}), 403

        ioc = db.session.get(IOC, ioc_id)

        incident.add_timeline_event(
            'ioc_unlinked',
            f'IOC desvinculado: {ioc.value if ioc else ioc_id}',
            user=current_user.username
        )

        db.session.delete(link)
        db.session.commit()

        return jsonify({'success': True}), 200

    except Exception as e:
        db.session.rollback()
        return _safe_error(e, "Error unlinking IOC")


# =============================================================================
# TIMELINE COMPLETO (notas + chat de sesion vinculada)
# =============================================================================

@bp.route('/<int:incident_id>/timeline', methods=['GET'])
@login_required
def get_full_timeline(incident_id):
    """
    Obtiene timeline completo del incidente.
    Incluye notas propias + mensajes del chat si hay sesion vinculada.
    """
    try:
        incident = db.session.get(Incident, incident_id)
        if not incident:
            return jsonify({'error': 'Incidente no encontrado'}), 404

        if not _check_incident_access(incident):
            return jsonify({'error': 'No autorizado'}), 403

        # Timeline propio del incidente
        timeline = list(incident.timeline or [])

        # Si hay sesion vinculada, agregar mensajes del chat
        if incident.session_id:
            try:
                from app.models.session import SessionMessage
                messages = SessionMessage.query.filter_by(
                    session_id=incident.session_id
                ).order_by(SessionMessage.created_at).all()

                for msg in messages:
                    timeline.append({
                        'type': 'chat_message',
                        'description': msg.content[:200] + ('...' if len(msg.content) > 200 else ''),
                        'user': msg.role,
                        'timestamp': msg.created_at.isoformat() if msg.created_at else None,
                        'llm_provider': msg.llm_provider,
                        'source': 'session'
                    })
            except Exception as e:
                logger.warning(f"Could not load session messages: {e}")

        # Ordenar por timestamp
        timeline.sort(key=lambda x: x.get('timestamp', ''))

        return jsonify({
            'success': True,
            'timeline': timeline,
            'session_id': incident.session_id
        }), 200

    except Exception as e:
        return _safe_error(e, "Error getting timeline")


# =============================================================================
# ESTADISTICAS DE INCIDENTES
# =============================================================================

@bp.route('/stats', methods=['GET'])
@login_required
def get_stats():
    """Estadisticas de incidentes para el dashboard"""
    try:
        from sqlalchemy import func

        # Scope queries to the current user's incidents unless admin.
        base_q = Incident.query
        if current_user.role != 'admin':
            base_q = base_q.filter(
                (Incident.created_by == current_user.id) |
                (Incident.assigned_to == current_user.id)
            )

        # Aggregate status counts in a single GROUP BY query instead of 5 counts.
        status_base = db.session.query(Incident.status, func.count(Incident.id))
        if current_user.role != 'admin':
            status_base = status_base.filter(
                (Incident.created_by == current_user.id) |
                (Incident.assigned_to == current_user.id)
            )
        status_counts = dict(status_base.group_by(Incident.status).all())

        stats = {
            'total': sum(status_counts.values()),
            'open': status_counts.get('open', 0),
            'investigating': status_counts.get('investigating', 0),
            'resolved': status_counts.get('resolved', 0),
            'closed': status_counts.get('closed', 0),
            'by_severity': {},
            'recent': []
        }

        # Por severidad (solo incidentes activos)
        sev_base = db.session.query(
            Incident.severity, func.count(Incident.id)
        ).filter(
            Incident.status.in_(['open', 'investigating'])
        )
        if current_user.role != 'admin':
            sev_base = sev_base.filter(
                (Incident.created_by == current_user.id) |
                (Incident.assigned_to == current_user.id)
            )
        severity_counts = sev_base.group_by(Incident.severity).all()

        for sev, count in severity_counts:
            if sev:
                stats['by_severity'][sev] = count

        # Recientes (respetando el mismo scope)
        recent = base_q.order_by(desc(Incident.created_at)).limit(5).all()
        stats['recent'] = [i.to_dict() for i in recent]

        return jsonify({'success': True, 'stats': stats}), 200

    except Exception as e:
        return _safe_error(e, "Error getting incident stats")