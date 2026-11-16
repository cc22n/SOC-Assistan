"""
Regla ÚNICA de acceso a un IOCAnalysis: solo su dueño o un admin.

La usan los reportes (PDF/DOCX) y el detalle JSON (/api/v2/analysis/<id>) para no duplicar el chequeo
(una copia olvidada = un IDOR). Los accesos ajenos quedan auditados como 'unauthorized_access'.
"""
from flask import jsonify
from flask_login import current_user

from app import db
from app.models.ioc import IOCAnalysis


def authorized_analysis(analysis_id):
    """(analisis, None) si el usuario actual puede verlo; (None, (respuesta, codigo)) si no existe o es ajeno."""
    analysis = db.session.get(IOCAnalysis, analysis_id)
    if not analysis:
        return None, (jsonify({'error': 'Análisis no encontrado'}), 404)
    if analysis.user_id != current_user.id and current_user.role != 'admin':
        from app.models.audit import AuditEvent
        AuditEvent.log('unauthorized_access', resource_type='analysis',
                       resource_id=analysis_id, success=False,
                       details={'reason': 'IDOR attempt'}, _commit=True)
        return None, (jsonify({'error': 'No autorizado'}), 403)
    return analysis, None
