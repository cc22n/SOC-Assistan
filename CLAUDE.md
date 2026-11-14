# SOC Agent — Guía para agentes

Plataforma Flask de threat intelligence para analistas SOC. 20 APIs de threat intel + Tavily (OSINT web) + 5 LLMs con routing. Entry point real: `wsgi.py` (no hay `run.py`).

## Comandos

```bash
# Tests (requiere Postgres local con BD soc_agent_test)
python -m pytest tests/unit -q          # suite completa (~375 tests, ~90s)
python -m pytest tests/unit/test_X.py -q  # un módulo

# App en desarrollo
flask run --debug                        # el CLI de Flask auto-carga .env
```

En scripts sueltos de Python, `.env` NO se auto-carga: usa `from dotenv import load_dotenv; load_dotenv('.env')` antes de `create_app`.

## Base de datos — Alembic

Migraciones en `migrations/versions/` (Flask-Migrate). Al cambiar un modelo:

```bash
flask db migrate -m "descripcion corta"   # autogenerate contra soc_agent (dev)
# revisar SIEMPRE el archivo generado en migrations/versions/ antes de aplicar
flask db upgrade                           # aplica a soc_agent (dev)
```

`soc_agent_test` en teoría no necesita el `ALTER TABLE`/migración manual porque `tests/unit/conftest.py` llama `db.create_all()` en cada corrida — pero **eso solo crea tablas que no existen**, nunca agrega columnas a una tabla ya existente. Si algún flujo (CI, u otro agente "espejando CI exacto") corre `flask db downgrade base && flask db upgrade head` contra `soc_agent_test`, esa BD también queda 100% gobernada por las migraciones — cualquier columna que no esté en `migrations/versions/` desaparece igual que en dev. Ya pasó una vez (columna `crtsh_data` agregada solo con `ALTER TABLE` manual, sin migración → un downgrade+upgrade de espejo-CI la borró de `soc_agent_test` y rompió 47 tests reproduciblemente). **Tratar siempre `soc_agent_test` como si estuviera sujeta a `flask db upgrade`, nunca asumir que el `create_all()` de conftest la salva.**

`autogenerate` no ordena bien tablas con FK circulares (ver `incidents`/`investigation_sessions` en la migración base) ni detecta objetos que no son metadata de modelos (extensiones como `pg_trgm`) — revisar el diff generado, no aplicarlo a ciegas. Además, la baseline (`b9a306dbac54`) tiene drift real contra la BD viva: pedirle `flask db migrate` hoy genera decenas de cambios no relacionados (borra índices GIN legítimos como `idx_censys_data`/`idx_ioc_value_trgm`, degrada JSONB→JSON en las tablas `mitre_*`, etc.). **Regla dura: si agregaste una columna con `ALTER TABLE` manual (o cualquier cambio de esquema fuera de Alembic), escribe tú mismo un archivo de migración mínimo a mano en `migrations/versions/`** (`down_revision` = la head actual, un solo `op.add_column(...)`/`op.drop_column(...)`) — no uses el autogenerate para eso, arrastra todo el drift de arriba. Verifica el archivo de verdad: dropea la columna, corre `flask db upgrade` contra dev **y** contra test (`FLASK_ENV=testing flask db upgrade`), confirma que la recrea, antes de darlo por bueno. Los `.sql` sueltos en `migrations/` (fuera de `versions/`) son historial pre-Alembic, ya no se ejecutan desde ningún lado (ver `migrations/LEGACY_SQL.md`).

En Windows con Postgres en español, agrega `?client_encoding=utf8` a la URL de psycopg2 o los errores de conexión dan `UnicodeDecodeError`.

## Convenciones obligatorias

- **Lista de APIs**: nunca hardcodear listas de nombres de APIs — usar `IOCAnalysis.api_source_names()` (derivada de las columnas `*_data` del modelo). Una API nueva = una columna `<nombre>_data` + cliente + entrada en `_is_api_compatible` + despacho en `async_executor._resolve_method`.
- **`risk_level`**: grafía canónica `CRÍTICO` (con tilde), garantizada por `@validates` en `IOCAnalysis`. No escribir filtros duales `in_(['CRÍTICO','CRITICO'])`.
- **Errores 500**: usar `safe_error_response(e, "contexto")` de `app/utils/responses.py`. No repetir el bloque `if current_app.debug` inline.
- **Auditoría**: `AuditEvent.log(...)` NO commitea por defecto. En rutas terminales (donde no hay commit posterior) pasar `_commit=True` o el evento se pierde.
- **Visibilidad de incidentes**: usar `Incident.is_visible_to(user)` / `Incident.visible_to(user)` / `Incident.visibility_criterion(user)`. No reimplementar la regla admin/creador/asignado.
- **Frontend**: `escapeHtml()` está definida UNA vez en `base.html` — usarla siempre al interpolar datos de APIs/LLM en `innerHTML`; no redefinirla por template.
- **CSP estricta (ALTO-11)**: `script-src` usa nonce + `strict-dynamic`, sin `'unsafe-inline'`. Todo `<script>` lleva `nonce="{{ csp_nonce() }}"`. **Prohibidos** los handlers inline (`onclick=`, `onchange=`…) y las URLs `javascript:`: usar `data-action` / `data-change` / `data-input` / `data-enter` (+ `data-args` como JSON, en Jinja con `|tojson`) que despacha `app/static/ui-actions.js`; la función destino debe ser global (`function nombre()`). Las plantillas que no extienden `base.html` deben cargar `ui-actions.js` ellas mismas. `tests/unit/test_csp.py` lo vigila. Verificar cambios de CSP en un navegador real: la consola NO muestra las violaciones de CSP de forma fiable (usar `report-uri` o un listener de `securitypolicyviolation`).
- **Crear IOCs**: `IOC.get_or_create(value, ioc_type, **defaults)` (atómico, SAVEPOINT ante la carrera por `uq_ioc_value_type`). Nunca `query.first()` + `IOC(...)`.
- **Transacciones**: un servicio que persiste no debe hacer `commit()` si el llamador es dueño de una transacción mayor. `SessionManager.add_ioc_to_session` acepta `commit=False` (solo flush); el llamador lo envuelve en `db.session.begin_nested()` (SAVEPOINT) y hace el commit final.
- **Incidentes**: severidades y estados viven en `Incident.VALID_SEVERITIES` / `VALID_STATUSES`; los cambios de estado pasan por `incident.transition_to()` (máquina de estados `STATUS_TRANSITIONS`, 409 si no es válida; reabrir limpia `resolved_at`). No asignar `incident.status` directamente.
- **Sin mocks en `app/`**: nunca importar `unittest.mock` ni detectar `Mock` en runtime; los tests parchean `requests.get/post` (ver fixture `_http_session_via_requests` en `conftest.py`).
- **Auth**: el logout es solo `POST` con `csrf_token` (nunca un enlace GET). El login hace un hash de relleno si el usuario no existe (igualar tiempos) y bloquea la cuenta tras 5 fallos/15 min (`app/utils/login_throttle.py`, cuenta por nombre intentado, exista o no). La cabecera `Host` se valida contra `ALLOWED_HOSTS` (`app/utils/hosts.py`): en producción tras un proxy con dominio propio hay que definirlo o todo da 400.
- **Dependencias**: antes de dar por buena una versión, probar una instalación LIMPIA (`python -m venv` + `pip install -r requirements.txt`), no solo el entorno conda: ya ocultó que SQLAlchemy 2.1 rompe `postgresql://` (psycopg v3) y que faltaba `tzdata`. `SQLAlchemy<2.1` es un tope obligatorio. Verificar CVEs contra OSV, no solo con informes.
- **RBAC**: decorator `@require_role('rol')` de `app/utils/auth.py` (jerarquía en `ROLE_HIERARCHY`), no checks inline de `current_user.role`.
- **Contenido web externo** (Tavily): tratarlo como no confiable — en prompts de síntesis marcarlo explícitamente y exigir citas por URL (ver `_summarize_web_results`).

## Documentos privados — NUNCA commitear

`BITACORA.md`, `AGENTE_CONTEXTO.md`, `CHANGELOG_BUGFIXES.md`, `PLAN-PENDIENTES.md`, `ROADMAP_FASE3.md` existen localmente, están en `.gitignore` y el historial de git fue purgado para eliminarlos (jul 2026). No usar `git add -f` con ellos. Al terminar una sesión de trabajo, actualizar `BITACORA.md` (skill `/bitacora`).

## Mapa rápido

- `app/services/llm_orchestrator.py` — routing LLM, chat, memoria entre sesiones (`_get_ioc_history`), grafo de correlación (`_get_related_iocs`)
- `app/services/deep_analysis_service.py` — deep analysis + agente OSINT de 2 pasos (planner LLM → Tavily → síntesis con citas), caché web TTL 24h
- `app/services/new_api_clients.py` — clientes de las 20 APIs + `TavilySearchClient`
- `app/services/async_executor.py` — ejecución paralela; mapa (api, tipo) → método
- `app/routes/api_v2_routes.py` — API REST principal (`/api/v2`)
- `tests/unit/conftest.py` — fixtures (usuarios por rol, clients autenticados, sample_ioc/analysis)
- `scripts/manual/` — scripts ad-hoc que llaman APIs reales; NO son la suite, no moverlos a tests/
