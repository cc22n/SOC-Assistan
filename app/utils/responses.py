"""
Helpers de respuesta HTTP compartidos.
"""
import logging
from typing import Any, Tuple

from flask import current_app, jsonify

logger = logging.getLogger(__name__)


def safe_error_response(error: Exception, context: str = "") -> Tuple[Any, int]:
    """
    Loguea la excepción con stack trace y responde 500 sin exponer
    detalles internos en producción (solo en modo debug se retorna str(e)).
    """
    logger.error(f"{context}: {error}", exc_info=True)
    if current_app.debug:
        return jsonify({'error': str(error)}), 500
    return jsonify({'error': 'Internal server error'}), 500
