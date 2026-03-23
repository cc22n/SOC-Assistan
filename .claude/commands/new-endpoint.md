# /new-endpoint — Crear Nuevo Endpoint Seguro

Crea un nuevo endpoint Flask siguiendo los patrones de seguridad obligatorios del proyecto SOC Agent.

## Instrucciones para el agente

Cuando el usuario pida crear un nuevo endpoint, solicita:
1. **Blueprint destino**: `main`, `api_v2`, `incident`, `auth`
2. **Método HTTP**: GET, POST, PUT, DELETE
3. **Ruta URL**: ej. `/api/v2/reports`
4. **Requiere auth**: ¿Sí/No?
5. **Tipo de respuesta**: JSON o HTML template

## Template obligatorio para endpoints JSON

```python
@{blueprint}_bp.route('{ruta}', methods=['{MÉTODO}'])
@login_required                          # OBLIGATORIO si maneja datos de usuario
@limiter.limit("30 per hour")           # OBLIGATORIO en endpoints que escriben
def nombre_endpoint():
    """Descripción del endpoint."""
    try:
        # 1. Validar input con Pydantic
        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON requerido'}), 400

        # validated = NombreSchema(**data)  # Siempre validar con schema

        # 2. Verificar ownership si accede a recursos de otro usuario
        # resource = db.session.get(Modelo, resource_id)  # NO .query.get()
        # if not resource:
        #     return jsonify({'error': 'No encontrado'}), 404
        # if resource.created_by != current_user.id and current_user.role != 'admin':
        #     return jsonify({'error': 'No autorizado'}), 403

        # 3. Lógica de negocio
        resultado = {}

        return jsonify(resultado), 200

    except ValidationError as e:
        return jsonify({'error': 'Datos inválidos', 'details': e.errors()}), 422
    except Exception as e:
        return _safe_error(e, "Error procesando solicitud")
```

## Checklist antes de guardar el endpoint

- [ ] `@login_required` presente (si aplica)
- [ ] Rate limiting aplicado (si escribe datos)
- [ ] Input validado con Pydantic schema
- [ ] `db.session.get()` usado (NO `.query.get()`)
- [ ] Verificación de ownership implementada
- [ ] `_safe_error()` usado en except genérico
- [ ] Ruta añadida a `app/docs/openapi.py`
- [ ] Test básico añadido en `tests/`

## Regla absoluta
**NUNCA** retornar `str(e)` directamente en JSON. Siempre usar `_safe_error(e, "mensaje genérico")`.
