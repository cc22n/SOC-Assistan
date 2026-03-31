"""
SOC Agent - Utilidades de Autenticación y Autorización
Fase 4 - T4B-04: RBAC básico

Roles definidos (en orden de privilegio ascendente):
  viewer         → Solo lectura (dashboard, historial)
  analyst        → Puede analizar IOCs y crear/gestionar sus incidentes
  senior_analyst → Puede exportar STIX y acceder a análisis profundo
  admin          → Acceso total

Uso:
    from app.utils.auth import require_role

    @bp.route('/admin/users')
    @login_required
    @require_role('admin')
    def list_users(): ...

    @bp.route('/export/stix')
    @login_required
    @require_role('senior_analyst')   # admin también tiene acceso
    def export_stix(): ...
"""
import functools
import logging
from typing import Union

from flask import jsonify
from flask_login import current_user

logger = logging.getLogger(__name__)

# Jerarquía de roles (mayor índice = mayor privilegio)
ROLE_HIERARCHY = ['viewer', 'analyst', 'senior_analyst', 'admin']


def _role_level(role: str) -> int:
    """Retorna el nivel numérico de un rol (mayor = más privilegios)."""
    try:
        return ROLE_HIERARCHY.index(role.lower())
    except ValueError:
        return -1  # Rol desconocido → sin acceso


def has_role(required_role: str) -> bool:
    """
    Verifica si el usuario actual tiene el rol requerido o uno superior.
    Seguro de llamar desde cualquier contexto Flask con usuario autenticado.
    """
    if not current_user or not current_user.is_authenticated:
        return False
    user_level = _role_level(getattr(current_user, 'role', ''))
    required_level = _role_level(required_role)
    return user_level >= required_level


def require_role(role: str):
    """
    Decorator que requiere un rol mínimo para acceder a la ruta.
    Los roles superiores en la jerarquía también tienen acceso.

    Retorna 403 JSON si el usuario no tiene el rol suficiente.
    Debe aplicarse DESPUÉS de @login_required.

    Args:
        role: Rol mínimo requerido ('viewer', 'analyst', 'senior_analyst', 'admin')
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not has_role(role):
                logger.warning(
                    f"RBAC denied: user={getattr(current_user, 'username', 'anonymous')} "
                    f"role={getattr(current_user, 'role', 'none')} "
                    f"required={role} endpoint={func.__name__}"
                )
                from app.models.audit import AuditEvent
                AuditEvent.log(
                    'rbac_denied',
                    success=False,
                    details={
                        'required_role': role,
                        'user_role': getattr(current_user, 'role', None),
                        'endpoint': func.__name__,
                    }
                )
                return jsonify({
                    'error': 'Forbidden',
                    'message': f'Se requiere rol {role} o superior'
                }), 403
            return func(*args, **kwargs)
        return wrapper
    return decorator
