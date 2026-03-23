"""
SOC Agent - Flask + Pydantic Integration
Sprint 3

Decorador validate_request() que:
1. Parsea request.get_json()
2. Valida contra un schema Pydantic
3. Inyecta el objeto validado como primer argumento de la vista
4. Retorna 400 con errores claros si la validación falla

Uso:
    from app.schemas.api import AnalyzeRequest
    from app.schemas.validator import validate_request

    @bp.route('/analyze/enhanced', methods=['POST'])
    @login_required
    @validate_request(AnalyzeRequest)
    def analyze_enhanced(data: AnalyzeRequest):
        # data ya está validado y tipado
        ioc_value = data.ioc
        ioc_type = data.type  # IOCType enum o None
        ...
"""
import logging
from functools import wraps
from typing import Type

from flask import jsonify, request
from pydantic import BaseModel, ValidationError

logger = logging.getLogger(__name__)


def validate_request(schema: Type[BaseModel]):
    """
    Decorador que valida el JSON body contra un schema Pydantic.

    Reemplaza @require_json + validación manual.
    El objeto validado se pasa como primer argumento a la vista.

    Args:
        schema: Clase Pydantic (ej: AnalyzeRequest)

    Returns:
        Decorator que inyecta el schema validado

    Ejemplo:
        @validate_request(AnalyzeRequest)
        def my_endpoint(data: AnalyzeRequest):
            print(data.ioc)  # Ya validado
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # 1. Verificar Content-Type
            json_data = request.get_json(silent=True)
            if json_data is None:
                return jsonify({
                    'error': 'Request must be JSON (Content-Type: application/json)',
                    'status_code': 400
                }), 400

            # 2. Validar contra schema
            try:
                validated = schema(**json_data)
            except ValidationError as e:
                # Formatear errores Pydantic de forma clara
                errors = []
                for err in e.errors():
                    field = ' → '.join(str(loc) for loc in err['loc'])
                    errors.append({
                        'field': field,
                        'message': err['msg'],
                        'type': err['type']
                    })

                logger.warning(
                    f"Validation error on {request.path}: "
                    f"{len(errors)} error(s) - {errors[0]['field']}: {errors[0]['message']}"
                )

                return jsonify({
                    'error': 'Validation error',
                    'details': errors,
                    'status_code': 422
                }), 422

            # 3. Inyectar schema validado como primer argumento
            return f(validated, *args, **kwargs)

        return wrapper
    return decorator


def validate_query_params(schema: Type[BaseModel]):
    """
    Similar a validate_request pero para query parameters (GET).

    Ejemplo:
        @validate_query_params(SearchParams)
        def search(params: SearchParams):
            print(params.q, params.page)
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            try:
                validated = schema(**request.args.to_dict())
            except ValidationError as e:
                errors = []
                for err in e.errors():
                    field = ' → '.join(str(loc) for loc in err['loc'])
                    errors.append({
                        'field': field,
                        'message': err['msg'],
                        'type': err['type']
                    })

                return jsonify({
                    'error': 'Invalid query parameters',
                    'details': errors,
                    'status_code': 422
                }), 422

            return f(validated, *args, **kwargs)

        return wrapper
    return decorator
