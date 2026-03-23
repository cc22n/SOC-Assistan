# CHANGELOG DE CORRECCIONES DE BUGS — SOC Agent
> **Para el agente de IA que continúa el desarrollo**
> Fecha: 2026-03-20 | Fase: Post-Fase 2 | Auditor: Claude Sonnet 4.6

---

## RESUMEN EJECUTIVO

Se completaron **2 rondas de auditoría de seguridad y código** sobre el proyecto SOC Agent.
En total se corrigieron **19 bugs** distribuidos en 7 archivos.
Este documento describe **exactamente qué cambió, dónde y por qué**, para que la próxima fase de desarrollo no revierta estas correcciones ni introduzca los mismos patrones.

---

## ARCHIVOS MODIFICADOS

| Archivo | Bugs corregidos |
|---------|----------------|
| `app/config.py` | 1 |
| `app/__init__.py` | 2 |
| `app/routes/auth.py` | 1 |
| `app/routes/api_v2_routes.py` | 3 |
| `app/routes/incident_routes.py` | 6 |
| `app/routes/main.py` | 2 |
| `app/models/ioc.py` | 2 |
| `app/schemas/api.py` | 1 |
| `app/services/llm_orchestrator.py` | 1 |
| `app/docs/openapi.py` | 1 (archivo nuevo en fase 2) |

---

## CORRECCIONES DETALLADAS

---

### [CRÍTICO] `app/config.py` — `ProductionConfig.init_app()` firma incorrecta

**Problema:** El método era `def init_app(cls):` sin parámetro `app`.
Al llamarlo desde `__init__.py` con `cfg.init_app(app)`, Python lanzaba
`TypeError: init_app() takes 1 positional argument but 2 were given`,
impidiendo que la aplicación arrancara en `FLASK_ENV=production`.

**Fix aplicado:**
```python
# ANTES
@classmethod
def init_app(cls):

# DESPUÉS
@classmethod
def init_app(cls, app=None):
    """Valida configuracion critica antes de arrancar en produccion."""
```

**Regla para futuras fases:** Si se agrega lógica de validación de configuración en
`ProductionConfig`, el método siempre debe aceptar `app=None` como parámetro opcional
para ser compatible con el patrón `cfg.init_app(app)` del factory.

---

### [CRÍTICO] `app/__init__.py` — `ProductionConfig.init_app()` nunca se invocaba

**Problema:** `app.config.from_object(cfg)` carga atributos de clase pero no llama métodos.
La validación de `SECRET_KEY` en producción era código muerto.

**Fix aplicado en `create_app()`:**
```python
# DESPUÉS (líneas 35-40)
cfg = config[config_name]
app.config.from_object(cfg)

# Validar configuración crítica
if hasattr(cfg, 'init_app'):
    cfg.init_app(app)
```

**Regla para futuras fases:** El patrón `cfg.init_app(app)` DEBE mantenerse después de
`app.config.from_object(cfg)`. No lo elimines aunque parezca redundante.

---

### [ALTO] `app/__init__.py` — `load_user` usaba `User.query.get()` deprecado

**Problema:** SQLAlchemy 2.x elimina `Query.get()`. Rompía el login de todos los usuarios.

**Fix aplicado:**
```python
# ANTES
return User.query.get(int(user_id))

# DESPUÉS
return db.session.get(User, int(user_id))
```

**Regla para futuras fases:** En todo el proyecto, usar `db.session.get(Modelo, id)`.
Nunca usar `Modelo.query.get(id)`. El linter puede no detectarlo como error pero falla en runtime.

---

### [ALTO] `app/routes/incident_routes.py` — 10 usos de `.query.get()` deprecado

**Problema:** Mismo problema que arriba pero en `incident_routes.py`.

**Fix aplicado:** Reemplazados todos los usos en las funciones:
- `create_incident()` línea 113: `IOC.query.get(ioc_id)` → `db.session.get(IOC, ioc_id)`
- `get_incident()` línea 216: `Incident.query.get()` → `db.session.get(Incident, ...)`
- `update_incident()` líneas 252, 282: `Incident.query.get()`, `User.query.get()` → `db.session.get()`
- `change_status()` línea 325: `Incident.query.get()` → `db.session.get(Incident, ...)`
- `add_note()` línea 388: `Incident.query.get()` → `db.session.get(Incident, ...)`
- `link_iocs()` líneas 443, 460: `Incident.query.get()`, `IOC.query.get()` → `db.session.get()`
- `unlink_ioc()` líneas 520, 525: `Incident.query.get()`, `IOC.query.get()` → `db.session.get()`
- `get_full_timeline()` línea 555: `Incident.query.get()` → `db.session.get(Incident, ...)`

**Nota:** En `main.py` la línea `Incident.query.get_or_404()` NO fue tocada porque
`get_or_404()` es un método Flask-SQLAlchemy válido y no está deprecado.

---

### [ALTO] `app/routes/incident_routes.py` — `create_incident()` exponía `str(e)` en producción

**Problema:** El único handler de error que no usaba `_safe_error()`.

**Fix aplicado:**
```python
# ANTES
except Exception as e:
    db.session.rollback()
    logger.error(f"Error creating incident: {e}")
    return jsonify({'error': str(e)}), 500

# DESPUÉS
except Exception as e:
    db.session.rollback()
    return _safe_error(e, "Error creating incident")
```

**Regla para futuras fases:** TODOS los `except Exception as e` en rutas deben usar
`_safe_error(e, "contexto")` o el equivalente en `api_v2_routes.py` (`safe_error_response()`).
**Nunca** hacer `return jsonify({'error': str(e)})` en producción.

---

### [MEDIO] `app/routes/incident_routes.py` — `unlink_ioc()` podía crashear con NoneType

**Problema:** Si existía un `IncidentIOC` huérfano (incidente borrado sin CASCADE),
`Incident.query.get(incident_id)` devolvía `None` y `_check_incident_access(None)`
accedía a `None.created_by` → `AttributeError`.

**Fix aplicado:** Añadido guard explícito antes del access check:
```python
incident = db.session.get(Incident, incident_id)
if not incident:                                    # ← NUEVO
    return jsonify({'error': 'Incidente no encontrado'}), 404
if not _check_incident_access(incident):
    ...
```

**Regla para futuras fases:** Siempre verificar `if not objeto:` antes de pasarlo a
funciones de autorización. Las funciones `_check_incident_access()` asumen que el objeto no es `None`.

---

### [MEDIO] `app/docs/openapi.py` — `/api/docs` era público sin autenticación

**Problema:** El blueprint de documentación Swagger (nuevo en Fase 2) no tenía
`@login_required`. Cualquier persona podía ver toda la especificación de la API
(endpoints, parámetros, esquemas) sin cuenta.

**Fix aplicado:**
```python
# DESPUÉS
@docs_bp.route('/openapi.json')
@login_required                   # ← NUEVO
def openapi_spec():
    ...

@docs_bp.route('/')
@login_required                   # ← NUEVO
def swagger_ui():
    ...
```

**Regla para futuras fases:** Todo blueprint nuevo que exponga información interna del
sistema necesita `@login_required`. El CSRF-exempt del blueprint es correcto (solo sirve
JSON/HTML estático), pero la autenticación es obligatoria.

---

### [MEDIO] `app/services/llm_orchestrator.py` — `bare except: pass` ocultaba errores críticos

**Problema:** Si la inicialización de los 19 clientes API fallaba (import error, app context,
clave inválida), el error se descartaba en silencio y `api_clients` quedaba `{}`.
Los análisis fallaban después sin ningún log útil.

**Fix aplicado:**
```python
# ANTES
try:
    self._initialize_clients()
except:
    pass

# DESPUÉS
try:
    self._initialize_clients()
except Exception as e:
    logger.error(f"CRITICAL: Failed to initialize API clients: {e}", exc_info=True)
```

**Regla para futuras fases:** **Nunca usar `bare except: pass`** en ningún bloque del proyecto.
Siempre como mínimo `except Exception as e: logger.error(...)`. El `exc_info=True` incluye
el traceback completo en los logs, esencial para debugging.

---

### [MEDIO] `app/routes/main.py` — `/history` exponía análisis de todos los usuarios

**Problema:** El historial de análisis listaba registros de todos los usuarios sin filtrar
por el usuario autenticado. Un analista veía el trabajo de sus compañeros.

**Fix aplicado:**
```python
# ANTES
query = IOCAnalysis.query

# DESPUÉS
if current_user.role == 'admin':
    query = IOCAnalysis.query
else:
    query = IOCAnalysis.query.filter_by(user_id=current_user.id)
```

**Regla para futuras fases:** Cualquier endpoint de listado que devuelva datos personales
de investigación DEBE filtrar por `current_user.id` a menos que el usuario sea `admin`.
El patrón `if current_user.role == 'admin': ... else: ...filter_by(user_id=current_user.id)`
es el estándar del proyecto.

---

### [BAJO] `app/routes/main.py` — `search()` no escapaba metacaracteres LIKE

**Problema:** `IOC.value.contains(query_text)` sin `autoescape=True`.
Buscar `%` devolvía todos los IOCs. Buscar `100%` fallaba la comparación.
Con tablas grandes, `LIKE '%_%'` causaba full table scan.

**Fix aplicado:**
```python
# ANTES
IOC.value.contains(query_text)

# DESPUÉS
IOC.value.contains(query_text, autoescape=True)
```

Aplicado en las dos queries de `search()` (líneas de IOC y de IOCAnalysis).

---

### [ALTO] `app/routes/auth.py` — Open redirect via `javascript:` URI

**Problema:** `urlparse(next_page).netloc != ''` rechazaba `https://evil.com`
pero no `javascript:alert(1)` (netloc vacío en URIs javascript:).

**Fix aplicado:**
```python
# DESPUÉS (ya en el código)
if next_page:
    parsed = urlparse(next_page)
    if parsed.netloc != '' or parsed.scheme not in ('', 'http', 'https'):
        next_page = None
```

---

### [CRÍTICO] `app/models/ioc.py` — `APIUsage.date` evaluado en import, no por inserción

**Problema:** `default=datetime.utcnow().date` se evaluaba una vez al importar el módulo.
Todos los registros nuevos de `APIUsage` tenían la fecha de inicio del servidor.
Los contadores diarios de cuotas nunca se reiniciaban.

**Fix aplicado:**
```python
# ANTES
date = db.Column(db.Date, default=datetime.utcnow().date, index=True)

# DESPUÉS
date = db.Column(db.Date, default=lambda: datetime.utcnow().date(), index=True)
```

**Regla para futuras fases:** En columnas SQLAlchemy con `default=`, si el valor debe
calcularse en el momento de inserción (fechas, UUIDs, timestamps), SIEMPRE pasar una
**función callable** (lambda o referencia a función), nunca el valor evaluado directamente.
- ✅ `default=lambda: datetime.utcnow().date()`
- ✅ `default=datetime.utcnow` (referencia, no llamada)
- ❌ `default=datetime.utcnow()` (se evalúa una sola vez al definir la clase)
- ❌ `default=datetime.utcnow().date` (igual, se evalúa una sola vez)

---

### [CRÍTICO] `app/models/ioc.py` — Race condition en `generate_ticket_id()`

**Problema:** El `COUNT` y el `INSERT` no eran atómicos. Dos requests concurrentes
podían generar el mismo `SOC-YYYYMMDD-006`, causando `IntegrityError` → HTTP 500.

**Fix aplicado:** Advisory lock de PostgreSQL:
```python
@staticmethod
def generate_ticket_id():
    from sqlalchemy import text
    db.session.execute(text("SELECT pg_advisory_xact_lock(735201)"))
    today = datetime.utcnow().strftime('%Y%m%d')
    count = Incident.query.filter(
        Incident.ticket_id.like(f'SOC-{today}-%')
    ).count()
    return f"SOC-{today}-{count + 1:03d}"
```

**Nota:** El número `735201` es el lock ID arbitrario. Si se agrega otro advisory lock
en el proyecto, usar un número diferente.

---

### [ALTO] `app/schemas/api.py` — `session_id` era `Optional[str]` pero se usaba como `int`

**Problema:** Pydantic aceptaba `"session_id": "5"` (string) pero las queries de BD
esperaban un entero. El linking de IOCs a sesiones fallaba silenciosamente.

**Fix aplicado:**
```python
# ANTES
session_id: Optional[str] = Field(None, max_length=100, ...)

# DESPUÉS
session_id: Optional[int] = Field(None, ge=1, description='Investigation session ID')
```

Aplicado en `AnalyzeRequest`, `AnalyzeResponse`, `ChatMessageRequest`, y `ChatMessageResponse`.

---

### [ALTO] `app/routes/api_v2_routes.py` — Rate limiting ausente en endpoints core

**Problema:** `/analyze/enhanced` y `/chat/message` sin rate limit. Un usuario
autenticado podía agotar cuotas de APIs en segundos (SecurityTrails: 2/día).

**Fix aplicado:**
```python
@bp.route('/analyze/enhanced', methods=['POST'])
@login_required
@limiter.limit("30 per hour")   # ← NUEVO
@limiter.limit("5 per minute")  # ← NUEVO
@validate_request(AnalyzeRequest)
def analyze_enhanced(data):

@bp.route('/chat/message', methods=['POST'])
@login_required
@limiter.limit("60 per hour")   # ← NUEVO
@limiter.limit("10 per minute") # ← NUEVO
@validate_request(ChatMessageRequest)
def chat_message(data):
```

**Regla para futuras fases:** Todo endpoint que consuma APIs externas o recursos costosos
DEBE tener `@limiter.limit()`. Los límites actuales son conservadores; ajustar según el
plan de API keys disponibles.

---

### [ALTO] `app/routes/incident_routes.py` — IDOR: acceso sin verificar ownership

**Problema:** Ningún endpoint de incidentes verificaba si el usuario tenía derecho
sobre el incidente. Cualquier analista podía leer/modificar incidentes ajenos.

**Fix aplicado:** Función helper `_check_incident_access()` añadida y aplicada en todos los endpoints:
```python
def _check_incident_access(incident):
    if current_user.role == 'admin':
        return True
    if incident.created_by == current_user.id:
        return True
    if incident.assigned_to == current_user.id:
        return True
    return False
```

**Regla para futuras fases:** Todo endpoint que acceda a un recurso específico por ID
DEBE verificar ownership antes de operar. El patrón es:
```python
objeto = db.session.get(Modelo, id)
if not objeto: return 404
if not _check_acceso(objeto): return 403
# ... operar
```

---

### [MEDIA] `app/routes/incident_routes.py` — `_safe_error()` para todos los handlers

**Problema:** Los handlers de error retornaban `str(e)` directamente al cliente,
exponiendo detalles internos de la BD y paths del servidor.

**Fix aplicado:** Función `_safe_error()` añadida localmente en `incident_routes.py`:
```python
def _safe_error(e, context=""):
    logger.error(f"{context}: {e}", exc_info=True)
    from flask import current_app
    if current_app.debug:
        return jsonify({'error': str(e)}), 500
    return jsonify({'error': 'Internal server error'}), 500
```

En modo debug (`FLASK_DEBUG=1`) sí expone detalles para facilitar el desarrollo.
En producción siempre retorna el mensaje genérico.

---

### [BAJO] Sentry configurado con `traces_sample_rate=1.0` y `send_default_pii` por defecto

**Problema:** Enviaba el 100% de transacciones a Sentry.io, incluyendo IOCs,
resultados de APIs de threat intel y posibles datos PII.

**Fix aplicado:**
```python
sentry_sdk.init(
    dsn=sentry_dsn,
    integrations=[FlaskIntegration()],
    traces_sample_rate=0.05,   # 5% de transacciones
    send_default_pii=False,    # No enviar PII
)
```

---

## PATRONES PROHIBIDOS EN EL PROYECTO

El agente de IA **NO DEBE** usar estos patrones en ningún código nuevo:

```python
# ❌ PROHIBIDO - Query.get() deprecado SQLAlchemy 2.x
Modelo.query.get(id)

# ✅ CORRECTO
db.session.get(Modelo, id)

# ❌ PROHIBIDO - Exponer excepciones al cliente
return jsonify({'error': str(e)}), 500

# ✅ CORRECTO
return _safe_error(e, "contexto descriptivo")

# ❌ PROHIBIDO - Bare except que oculta errores
try:
    algo_critico()
except:
    pass

# ✅ CORRECTO
try:
    algo_critico()
except Exception as e:
    logger.error(f"Contexto: {e}", exc_info=True)

# ❌ PROHIBIDO - Default evaluado en definición de clase
date = db.Column(db.Date, default=datetime.utcnow().date())

# ✅ CORRECTO - Lambda evaluada en cada inserción
date = db.Column(db.Date, default=lambda: datetime.utcnow().date())

# ❌ PROHIBIDO - Nuevas rutas sin verificar ownership
@bp.route('/<int:id>', methods=['GET'])
@login_required
def get_resource(id):
    resource = db.session.get(Resource, id)
    return jsonify(resource.to_dict())   # cualquiera puede ver recursos ajenos

# ✅ CORRECTO
@bp.route('/<int:id>', methods=['GET'])
@login_required
def get_resource(id):
    resource = db.session.get(Resource, id)
    if not resource:
        return jsonify({'error': 'Not found'}), 404
    if not _check_access(resource):
        return jsonify({'error': 'No autorizado'}), 403
    return jsonify(resource.to_dict())

# ❌ PROHIBIDO - Nuevos blueprints/rutas sin @login_required cuando exponen datos internos
@new_bp.route('/internal-data')
def internal_data():
    return jsonify(sensitive_stuff)

# ✅ CORRECTO
@new_bp.route('/internal-data')
@login_required
def internal_data():
    return jsonify(sensitive_stuff)

# ❌ PROHIBIDO - Búsquedas LIKE sin escapar wildcards
Model.column.contains(user_input)

# ✅ CORRECTO
Model.column.contains(user_input, autoescape=True)
```

---

## ARQUITECTURA DE SEGURIDAD ACTUAL (Estado post-Fase 2)

### Capas de protección implementadas

```
Request entrante
    │
    ├── 1. Flask-Limiter (rate limiting por IP)
    │       └── Auth endpoints: 5/min, 20/hr (login), 3/min (register)
    │       └── Analysis: 5/min, 30/hr
    │       └── Chat: 10/min, 60/hr
    │
    ├── 2. Security Middleware (app/middleware/security.py)
    │       └── SQLi, XSS, CMDi, Path Traversal detection
    │       └── Request size limit (10MB)
    │       └── Session fixation protection
    │
    ├── 3. Pydantic Validation (app/schemas/)
    │       └── Tipos, longitudes, formatos, enums validados
    │       └── IOC type-specific validation
    │
    ├── 4. Flask-Login (@login_required)
    │       └── Todas las rutas excepto /, /auth/login, /auth/register, /api/v2/health
    │
    ├── 5. Ownership check (_check_incident_access, session.user_id == current_user.id)
    │       └── Incidentes: created_by o assigned_to
    │       └── Sesiones: user_id == current_user.id (admins ven todo)
    │
    ├── 6. SQLAlchemy ORM (parameterized queries)
    │       └── Previene SQL injection en todas las queries de BD
    │
    └── 7. safe_error_response / _safe_error
            └── Oculta detalles internos en producción
```

### Configuración crítica para producción

```bash
# Variables de entorno OBLIGATORIAS en producción:
SECRET_KEY=<min 32 chars, generado con secrets.token_hex(32)>
DATABASE_URL=postgresql://user:pass@host:5432/db
REDIS_URL=redis://host:6379/0
FLASK_ENV=production
SESSION_COOKIE_SECURE=true   # Solo HTTPS

# Variables OPCIONALES pero recomendadas:
SENTRY_DSN=<dsn>             # Error tracking (traces_sample_rate=0.05)
LOG_LEVEL=INFO
```

---

## BUGS PENDIENTES PARA PRÓXIMAS FASES

Los siguientes issues fueron identificados pero **no corregidos** en esta sesión
porque son mejoras de calidad, no bugs críticos:

| Issue | Archivo | Descripción | Prioridad |
|-------|---------|-------------|-----------|
| VULN-06 | `middleware/security.py:101` | Patrones SQLi sin `re.IGNORECASE` (bypass por mayúsculas). Bajo impacto porque se usa ORM. | Baja |
| CQ-02 | `session_manager.py:722` | N+1 queries en `get_session_summary_for_ui()`. Usar `joinedload`. | Media |
| CQ-03 | `session_manager.py:746` | Dos instancias de `SessionManager` coexisten (singleton en módulo + `get_session_manager()`). | Media |
| ARCH-01 | `api_v2_routes.py:44` | `get_orchestrator()` no es thread-safe (doble inicialización posible). Usar double-checked locking. | Media |
| CQ-07 | `async_executor.py:238` | `asyncio.get_event_loop()` deprecado en Python 3.10+. Migrar a `asyncio.run()`. | Media |

---

## NOTA PARA EL AGENTE DE IA

Al implementar nuevas funcionalidades en fases posteriores:

1. **Antes de crear un nuevo endpoint**, revisar la sección "Patrones Prohibidos" arriba.
2. **Si creas un nuevo modelo SQLAlchemy**, recordar `default=lambda: ...` para fechas.
3. **Si creas un nuevo blueprint**, asegurarte de añadir `@login_required` y registrarlo
   en `register_blueprints()` de `__init__.py`. Si es API JSON, también añadirlo a `csrf.exempt()`.
4. **Si el endpoint accede a recursos por ID**, siempre verificar ownership (ver patrón arriba).
5. **Si expones datos de búsqueda**, siempre filtrar por `current_user.id` salvo que el usuario sea admin.
6. **Todos los `except Exception`** deben loguear con `exc_info=True` y retornar errores genéricos al cliente.
7. **Cualquier nuevo endpoint costoso** (APIs externas, LLM) debe tener `@limiter.limit()`.

---

*Generado automáticamente por auditoría de seguridad. Última actualización: 2026-03-20.*
