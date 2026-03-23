# 🗺️ ROADMAP FASE 3 — Plan para llegar a 8.0/10

> **Objetivo**: Subir de **6.4/10 → 8.0/10**
> **Gap a cubrir**: +1.6 puntos
> **Estrategia**: Priorizar tests (mayor impacto), luego calidad de código, luego features

---

## 📊 Desglose de Puntos por Tarea

| # | Tarea | Categoría | Puntos | Prioridad | Esfuerzo |
|---|---|---|---|---|---|
| 1 | Tests unitarios ≥60% cobertura | Robustez | +0.8 | 🔴 CRÍTICA | Alto |
| 2 | Type hints completos en servicios | Calidad | +0.3 | 🟡 ALTA | Medio |
| 3 | Logging estructurado JSON | Calidad | +0.3 | 🟡 ALTA | Medio |
| 4 | Validación Content-Length/payload | Seguridad | +0.2 | 🟡 ALTA | Bajo |
| 5 | Variables de entorno validadas al arranque | Seguridad | +0.2 | 🟡 ALTA | Bajo |
| 6 | Paginación en endpoints REST API | Robustez | +0.2 | 🟢 MEDIA | Medio |
| 7 | OpenAPI spec completa (todos endpoints) | Calidad | +0.3 | 🟢 MEDIA | Medio |
| 8 | Health check mejorado (`/api/v2/health`) | Arquitectura | +0.1 | 🟢 MEDIA | Bajo |
| **Total** | | | **+2.4** | | |

> Nota: Con +2.4 disponibles, se puede llegar a 8.0+ con margen. Las tareas 1-5 son suficientes.

---

## 🔴 PRIORIDAD 1 — Tests Unitarios (+0.8 pts)

### Objetivo
Cobertura ≥60% en módulos críticos: `routes/`, `services/`, `models/`

### Archivos a crear/completar
```
tests/
├── test_auth.py           ← Login, logout, registro, open redirect
├── test_main_routes.py    ← Dashboard, historial, búsqueda, IDOR
├── test_incident_routes.py ← CRUD, ownership, acceso no autorizado
├── test_api_v2.py         ← /analyze, /chat, rate limiting
├── test_models.py         ← IOC, Incident, User, ticket_id únicos
└── conftest.py            ← Fixtures: app, db, users, IOCs de prueba
```

### Tests críticos que DEBEN existir

```python
# test_main_routes.py
def test_history_analyst_only_sees_own(client, analyst_user, other_user):
    """Analista NO debe ver análisis de otros usuarios."""
    ...

def test_search_like_injection(client):
    """Búsqueda con % y _ no debe hacer LIKE injection."""
    response = client.get('/search?q=%25admin%25')
    assert response.status_code == 200
    # No debe crashear ni retornar todos los registros

# test_incident_routes.py
def test_incident_access_unauthorized(client, analyst_user, other_incident):
    """Analista no puede editar incidente de otro usuario."""
    response = client.put(f'/api/v2/incidents/{other_incident.id}', ...)
    assert response.status_code == 403

def test_incident_not_found_returns_404(client):
    """Incidente inexistente retorna 404, no 500."""
    response = client.get('/api/v2/incidents/99999')
    assert response.status_code == 404

# test_api_v2.py
def test_rate_limit_analyze(client):
    """Más de 5 requests/minuto en /analyze/enhanced devuelve 429."""
    ...

def test_health_check_structure(client):
    """Health check incluye db_status y no expone stack traces."""
    response = client.get('/api/v2/health')
    data = response.get_json()
    assert 'db_status' in data
    assert 'traceback' not in str(data)
```

### Fixtures en conftest.py
```python
@pytest.fixture
def app():
    app = create_app('testing')
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()

@pytest.fixture
def admin_user(app):
    user = User(username='admin', role='admin', ...)
    db.session.add(user)
    db.session.commit()
    return user

@pytest.fixture
def analyst_user(app):
    user = User(username='analyst', role='analyst', ...)
    ...
```

### Comando para ejecutar tests
```bash
pytest tests/ -v --cov=app --cov-report=term-missing --cov-fail-under=60
```

---

## 🟡 PRIORIDAD 2 — Type Hints en Servicios (+0.3 pts)

### Archivos a actualizar
- `app/services/threat_intel.py` — métodos de consulta a APIs
- `app/services/llm_orchestrator.py` — métodos de análisis LLM
- `app/routes/incident_routes.py` — helpers `_safe_error`, `_check_incident_access`

### Ejemplo de antes/después
```python
# ANTES
def analyze_ip(self, ip, services=None):
    ...

# DESPUÉS
from typing import Optional, Dict, Any, List

def analyze_ip(
    self,
    ip: str,
    services: Optional[List[str]] = None
) -> Dict[str, Any]:
    ...
```

---

## 🟡 PRIORIDAD 3 — Logging Estructurado JSON (+0.3 pts)

### Objetivo
Todos los logs en formato JSON para facilitar ingestión por SIEM/Elasticsearch.

### Implementación en `app/__init__.py`
```python
import logging
import json

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_data = {
            'timestamp': self.formatTime(record),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        # Añadir correlation ID si existe en el contexto de Flask
        from flask import g, has_request_context
        if has_request_context():
            log_data['request_id'] = getattr(g, 'request_id', None)
            log_data['user_id'] = getattr(g, 'user_id', None)
        return json.dumps(log_data)

def configure_logging(app):
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)
```

### Correlation ID por request
```python
# En __init__.py, before_request hook:
@app.before_request
def set_request_context():
    import uuid
    g.request_id = str(uuid.uuid4())
    if current_user.is_authenticated:
        g.user_id = current_user.id
```

---

## 🟡 PRIORIDAD 4 — Validación de Payload (+0.2 pts)

### Problema
Requests con payloads gigantes (ej. 100MB de texto) pueden causar DoS.

### Fix en `app/__init__.py`
```python
# Limitar tamaño máximo de request
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB

# Handler para payload demasiado grande
@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({'error': 'Payload demasiado grande. Máximo 16MB.'}), 413
```

### Fix en endpoints de análisis
```python
# En /api/v2/analyze/enhanced, validar longitud de IOC
if len(data.get('ioc_value', '')) > 2048:
    return jsonify({'error': 'IOC demasiado largo. Máximo 2048 caracteres.'}), 422
```

---

## 🟡 PRIORIDAD 5 — Variables de Entorno al Arranque (+0.2 pts)

### Problema
El servidor arranca aunque falten API keys críticas. Solo falla en runtime.

### Fix en `ProductionConfig.init_app()`
```python
REQUIRED_VARS = [
    'SECRET_KEY',
    'DATABASE_URL',
]

WARN_IF_MISSING = [
    'VIRUSTOTAL_API_KEY',
    'ABUSEIPDB_API_KEY',
    'REDIS_URL',
    'SENTRY_DSN',
]

@classmethod
def init_app(cls, app=None):
    # Validar requeridas (crash si faltan)
    for var in cls.REQUIRED_VARS:
        if not os.environ.get(var):
            raise RuntimeError(f"Variable de entorno requerida faltante: {var}")

    # Advertir opcionales
    for var in cls.WARN_IF_MISSING:
        if not os.environ.get(var):
            import warnings
            warnings.warn(f"Variable opcional faltante: {var}. Funcionalidad reducida.", stacklevel=2)
```

---

## 🟢 PRIORIDAD 6 — Paginación en API REST (+0.2 pts)

### Endpoints a actualizar
- `GET /api/v2/incidents` — añadir `?page=1&per_page=20`
- `GET /api/v2/iocs` — si existe

### Respuesta estándar paginada
```json
{
    "items": [...],
    "pagination": {
        "page": 1,
        "per_page": 20,
        "total": 150,
        "pages": 8,
        "has_next": true,
        "has_prev": false
    }
}
```

---

## 🟢 PRIORIDAD 7 — OpenAPI Spec Completa (+0.3 pts)

### Endpoints faltantes en la spec actual
Revisar `app/docs/openapi.py` y asegurarse de que todos los endpoints de `incident_routes.py` y `api_v2_routes.py` tengan:
- Descripción
- Parámetros de query/path documentados
- Request body schema referenciado
- Todos los response codes (200, 400, 401, 403, 404, 422, 429, 500)
- Tags correctos

---

## 🟢 PRIORIDAD 8 — Health Check Mejorado (+0.1 pts)

### Estado actual
```json
{"status": "ok", "db_status": "ok/error"}
```

### Estado objetivo
```json
{
    "status": "healthy",
    "version": "2.0.0",
    "timestamp": "2026-03-20T12:00:00Z",
    "components": {
        "database": {"status": "ok", "latency_ms": 5},
        "redis": {"status": "ok", "latency_ms": 1},
        "threat_intel_apis": {"configured": 19, "active": 15}
    },
    "uptime_seconds": 3600
}
```

---

## 📅 Timeline Sugerido

```
Sesión 1 (esta): Setup ambiente (DONE ✅) + Empezar tests (conftest + auth tests)
Sesión 2:        Completar tests (incident, api_v2, main_routes)
Sesión 3:        Type hints + Logging estructurado
Sesión 4:        Validación payload + Variables entorno + Health check
Sesión 5:        Paginación API + OpenAPI completa
Sesión 6:        Revisión final + auditoría /audit + calificación 8.0
```

---

## ✅ Checklist de Completitud Fase 3

- [ ] `tests/conftest.py` con fixtures básicos
- [ ] `tests/test_auth.py` — ≥5 tests
- [ ] `tests/test_main_routes.py` — ≥5 tests (incluye IDOR test)
- [ ] `tests/test_incident_routes.py` — ≥8 tests
- [ ] `tests/test_api_v2.py` — ≥5 tests
- [ ] Cobertura ≥60% (`pytest --cov`)
- [ ] Type hints en `threat_intel.py`
- [ ] Type hints en `llm_orchestrator.py`
- [ ] `JSONFormatter` implementado
- [ ] Correlation ID en requests
- [ ] `MAX_CONTENT_LENGTH = 16MB`
- [ ] Handler 413 implementado
- [ ] `REQUIRED_VARS` validadas en `ProductionConfig`
- [ ] Paginación en `GET /api/v2/incidents`
- [ ] OpenAPI spec cubre todos los endpoints
- [ ] Health check con latencias
- [ ] `/audit` da score ≥8.0
- [ ] `BITACORA.md` actualizada con Fase 3
