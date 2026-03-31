"""
SOC Agent - Audit Log Inmutable
Fase 4 - T4A-02

Tabla audit_events: registro append-only de todas las acciones relevantes.
Decorator @audit_action para anotar rutas/funciones.

Uso:
    from app.models.audit import AuditEvent, audit_action

    @bp.route('/login', methods=['POST'])
    @audit_action('login')
    def login(): ...

    # Manual:
    AuditEvent.log('analyze_ioc', resource_type='ioc', resource_id=ioc_id,
                   details={'ioc': '1.2.3.4', 'risk': 'ALTO'})
"""
import functools
import logging
from datetime import datetime
from typing import Any, Dict, Optional

from flask import request, g
from flask_login import current_user
from sqlalchemy.dialects.postgresql import JSONB

from app import db

logger = logging.getLogger(__name__)


class AuditEvent(db.Model):
    """
    Registro de auditoría inmutable.
    Solo se permite INSERT — nunca UPDATE ni DELETE.
    """
    __tablename__ = 'audit_events'

    id = db.Column(db.Integer, primary_key=True)
    # Quién hizo la acción
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)
    username = db.Column(db.String(80), nullable=True)  # Copia desnormalizada para historial

    # Qué hizo
    action = db.Column(db.String(80), nullable=False, index=True)  # 'login', 'analyze_ioc', etc.
    resource_type = db.Column(db.String(50), nullable=True)         # 'ioc', 'incident', 'session'
    resource_id = db.Column(db.Integer, nullable=True)

    # Detalles adicionales (JSONB para búsquedas eficientes)
    details = db.Column(JSONB, nullable=True)

    # Contexto de la solicitud
    ip_address = db.Column(db.String(45), nullable=True)    # IPv4/IPv6
    user_agent = db.Column(db.String(300), nullable=True)
    request_id = db.Column(db.String(36), nullable=True)    # correlation ID (T3B-05)

    # Resultado
    success = db.Column(db.Boolean, default=True, nullable=False)

    # Cuándo
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    __table_args__ = (
        db.Index('ix_audit_user_created', 'user_id', 'created_at'),
        db.Index('ix_audit_action_created', 'action', 'created_at'),
        db.Index('ix_audit_resource', 'resource_type', 'resource_id'),
    )

    @classmethod
    def log(
        cls,
        action: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        success: bool = True,
        user_id: Optional[int] = None,
        username: Optional[str] = None,
    ) -> Optional['AuditEvent']:
        """
        Registra un evento de auditoría.
        Captura automáticamente IP, user-agent y correlation ID del contexto Flask.
        Nunca lanza excepciones — falla silenciosamente para no interrumpir el flujo.
        """
        try:
            # Intentar obtener usuario del contexto Flask
            resolved_user_id = user_id
            resolved_username = username
            if resolved_user_id is None:
                try:
                    if current_user.is_authenticated:
                        resolved_user_id = current_user.id
                        resolved_username = current_user.username
                except Exception:
                    pass

            # Contexto de request
            ip = None
            ua = None
            req_id = None
            try:
                ip = request.remote_addr
                ua = request.headers.get('User-Agent', '')[:300]
                req_id = getattr(g, 'request_id', None)
            except RuntimeError:
                pass  # Fuera de contexto HTTP (CLI, tests, etc.)

            event = cls(
                user_id=resolved_user_id,
                username=resolved_username,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                details=details,
                ip_address=ip,
                user_agent=ua,
                request_id=req_id,
                success=success,
            )
            db.session.add(event)
            db.session.commit()
            return event

        except Exception as exc:
            logger.error(f"AuditEvent.log failed for action='{action}': {exc}", exc_info=True)
            try:
                db.session.rollback()
            except Exception:
                pass
            return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.username,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'details': self.details,
            'ip_address': self.ip_address,
            'success': self.success,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f'<AuditEvent {self.action} user={self.user_id} at={self.created_at}>'


# =============================================================================
# DECORATOR
# =============================================================================

def audit_action(
    action: str,
    resource_type: Optional[str] = None,
    get_resource_id=None,
):
    """
    Decorator para registrar automáticamente acciones en el audit log.

    Args:
        action: Nombre de la acción (ej: 'login', 'analyze_ioc', 'delete_incident')
        resource_type: Tipo del recurso afectado (ej: 'ioc', 'incident')
        get_resource_id: Callable opcional que recibe el resultado de la función
                         y retorna el resource_id a registrar.

    Uso:
        @bp.route('/login', methods=['POST'])
        @audit_action('login')
        def login(): ...

        @bp.route('/incidents/<int:incident_id>', methods=['DELETE'])
        @audit_action('delete_incident', resource_type='incident',
                      get_resource_id=lambda result, kwargs: kwargs.get('incident_id'))
        def delete_incident(incident_id): ...
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)

            # Determinar éxito según código HTTP si es respuesta Flask
            success = True
            try:
                # flask Response o tuple (body, status)
                if isinstance(result, tuple):
                    status_code = result[1] if len(result) > 1 else 200
                    success = int(status_code) < 400
                elif hasattr(result, 'status_code'):
                    success = result.status_code < 400
            except Exception:
                pass

            # Obtener resource_id
            res_id = None
            if get_resource_id:
                try:
                    res_id = get_resource_id(result, kwargs)
                except Exception:
                    pass

            AuditEvent.log(
                action=action,
                resource_type=resource_type,
                resource_id=res_id,
                success=success,
            )

            return result
        return wrapper
    return decorator
