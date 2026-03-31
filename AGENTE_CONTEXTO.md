# 🤖 AGENTE_CONTEXTO.md — Contexto Rápido para Agentes Claude

> **Lee este archivo PRIMERO** antes de trabajar en el proyecto SOC Agent.
> Última actualización: 2026-03-20 | Fase: 2 completada → Fase 3 en curso

---

## 📋 ¿Qué es este proyecto?

**SOC Agent** es una plataforma Flask de inteligencia de amenazas para analistas de seguridad (SOC).
Permite analizar IOCs (Indicators of Compromise: IPs, dominios, hashes, URLs) consultando 19 APIs de threat intel y generando análisis con 4 LLMs.

### Stack técnico
| Componente | Tecnología |
|---|---|
| Backend | Flask 3.x + Python 3.11 |
| Base de datos | PostgreSQL + SQLAlchemy 2.x |
| Auth | Flask-Login + Flask-WTF CSRF |
| Validación | Pydantic v2 |
| Rate limiting | Flask-Limiter |
| Cache | Flask-Caching |
| LLMs | XAI/Grok, OpenAI GPT-4o-mini, Groq/Llama, Gemini |
| Threat Intel APIs | 19 APIs (VirusTotal, AbuseIPDB, Shodan, OTX, GreyNoise, URLhaus, etc.) |
| Monitoreo | Sentry (`traces_sample_rate=0.05`, `send_default_pii=False`) |

---

## 📁 Estructura de archivos clave

```
agentesoc/
├── app/
│   ├── __init__.py          ← Application factory, extensiones
│   ├── config.py            ← Config por entorno (Dev/Prod/Test)
│   ├── models/
│   │   ├── ioc.py           ← IOC, IOCAnalysis, Incident, APIUsage
│   │   └── user.py          ← User model (Flask-Login)
│   ├── routes/
│   │   ├── auth.py          ← Login/logout/register
│   │   ├── main.py          ← Dashboard, historial, búsqueda, incidentes
│   │   ├── api_v2_routes.py ← API REST v2 (/api/v2/...)
│   │   └── incident_routes.py ← CRUD completo de incidentes
│   ├── services/
│   │   ├── threat_intel.py  ← Consulta las 19 APIs en paralelo
│   │   └── llm_orchestrator.py ← Orquesta los 4 LLMs
│   ├── schemas/
│   │   └── api.py           ← Pydantic v2 schemas de request/response
│   └── docs/
│       └── openapi.py       ← Swagger UI + OpenAPI 3.0 spec
├── .claude/
│   └── commands/            ← Skills/slash commands para este agente
│       ├── audit.md         ← /audit — auditoría completa
│       ├── bitacora.md      ← /bitacora — actualizar BITACORA.md
│       ├── check-patterns.md ← /check-patterns — anti-patrones
│       ├── complete-task.md ← /complete-task T3A-01 — marcar tarea completada
│       ├── fase-status.md   ← /fase-status — estado actual
│       ├── mejora-status.md ← /mejora-status — progreso del plan maestro
│       ├── new-endpoint.md  ← /new-endpoint — crear endpoint seguro
│       └── run-tests.md     ← /run-tests — ejecutar suite y ver cobertura
├── AGENTE_CONTEXTO.md       ← ESTE ARCHIVO
├── BITACORA.md              ← Historial de cambios por fase
├── PLAN-MEJORAS.md          ← Plan maestro 6.4→9.5 (3 fases, 27 tareas)
├── ROADMAP_FASE3.md         ← Detalle técnico de Fase 3
├── propuestas-mejora.md     ← Análisis técnico profundo (origen del plan)
└── CHANGELOG_BUGFIXES.md    ← Detalle técnico de todos los bug fixes
```

---

## 🚦 Estado actual del proyecto

### Calificación: **6.4/10** (al final de Fase 2)

| Área | Score | Detalles |
|---|---|---|
| Seguridad | 5.5/10 | Auth OK, faltan tests de penetración, CSRF en APIs |
| Calidad código | 6.5/10 | Patrones deprecados eliminados, faltan type hints |
| Robustez | 6.0/10 | Validación Pydantic presente, faltan edge cases |
| Arquitectura | 8.0/10 | Factory pattern sólido, blueprints bien separados |

---

## ⛔ PATRONES PROHIBIDOS — NUNCA USES ESTOS

```python
# ❌ PROHIBIDO — SQLAlchemy deprecado
Model.query.get(id)           # Usar: db.session.get(Model, id)

# ❌ PROHIBIDO — expone errores internos en producción
return jsonify({'error': str(e)}), 500
# Usar: return _safe_error(e, "mensaje genérico")

# ❌ PROHIBIDO — silencia errores sin log
except:
    pass
# Usar: except Exception as e: logger.error(f"...: {e}", exc_info=True)

# ❌ PROHIBIDO — LIKE injection
IOC.value.contains(user_input)
# Usar: IOC.value.contains(user_input, autoescape=True)

# ❌ PROHIBIDO — acceso sin verificar ownership
incident = db.session.get(Incident, id)
# Siempre verificar: if incident.created_by != current_user.id and role != 'admin': 403
```

---

## ✅ PATRONES OBLIGATORIOS

```python
# ✅ SQLAlchemy 2.x correcto
resource = db.session.get(Model, resource_id)
if not resource:
    return jsonify({'error': 'No encontrado'}), 404

# ✅ Verificación de ownership
if not _check_incident_access(incident):
    return jsonify({'error': 'No autorizado'}), 403

# ✅ Error seguro (str(e) solo en DEBUG)
return _safe_error(e, "Error procesando solicitud")

# ✅ Búsqueda segura
IOC.value.contains(query_text, autoescape=True)

# ✅ Rate limiting en endpoints de escritura
@limiter.limit("30 per hour")
@limiter.limit("5 per minute")
```

---

## 🏗️ Arquitectura de seguridad (7 capas)

```
[Cliente]
    │
    ▼
1. CSRF Protection (Flask-WTF) ──── Exempto: blueprints API (api_v2, incident, docs)
    │
    ▼
2. Rate Limiting (Flask-Limiter) ── /analyze/enhanced: 30/h + 5/min
    │                               /chat/message: 60/h + 10/min
    ▼
3. Authentication (Flask-Login) ─── @login_required en todas las rutas de datos
    │
    ▼
4. Authorization (IDOR) ──────────── _check_incident_access() verifica created_by/assigned_to
    │
    ▼
5. Input Validation (Pydantic v2) ── Todos los endpoints POST/PUT validan schema
    │
    ▼
6. SQL Safety ────────────────────── autoescape=True, ORM parametrizado
    │
    ▼
7. Error Handling ────────────────── _safe_error(): str(e) solo en DEBUG mode
```

---

## 📌 Reglas que SIEMPRE aplican en este proyecto

1. **Al terminar tu sesión**, actualiza `BITACORA.md` con `/bitacora`
2. **Antes de crear un endpoint**, usa `/new-endpoint` como template
3. **Si encuentras un bug**, regístralo en `BITACORA.md` aunque no lo corrijas
4. **No rompas autenticación**: todas las rutas `/dashboard`, `/history`, `/incidents`, `/analyze`, `/chat`, `/api-stats`, `/search` llevan `@login_required`
5. **ProductionConfig.init_app(cls, app=None)** — el parámetro `app=None` es intencional, no lo elimines
6. **`get_or_404()` en `main.py`** es válido y no está deprecado — no lo cambies
7. **`session_id` es `Optional[int]`** en todos los schemas Pydantic (no `str`)

---

## 🗺️ Próximos objetivos (ver PLAN-MEJORAS.md)

> Plan maestro: **6.4 → 9.5/10** en 3 fases
> Ver `PLAN-MEJORAS.md` para el detalle completo y checklist de tareas.

### Fase 3 (activa) — 6.4 → 8.0
- [ ] Tests unitarios cobertura ≥60% (T3A-01 a T3A-06)
- [ ] Type hints en servicios críticos (T3B-01 a T3B-03)
- [ ] Logging estructurado JSON + correlation ID (T3B-04, T3B-05)
- [ ] MAX_CONTENT_LENGTH + validación payload (T3C-01, T3C-02)
- [ ] Variables entorno validadas al arranque (T3C-03)
- [ ] Paginación en /incidents (T3C-04)
- [ ] Health check con latencias (T3C-05)
- [ ] OpenAPI spec completa (T3C-06)

### Fase 4 (siguiente) — 8.0 → 9.0
- [ ] Sanitización prompts LLM anti-injection (T4A-01)
- [ ] Audit log inmutable (T4A-02)
- [ ] Circuit breakers para APIs externas (T4B-01)
- [ ] RBAC ANALYST/SENIOR/ADMIN (T4B-04)

### Fase 5 (futuro) — 9.0 → 9.5+
- [ ] Notificaciones in-app (T5A-01)
- [ ] Webhooks outbound Slack/Teams (T5A-02)
- [ ] Celery + Redis async (T5B-01)

---

## 🔑 Variables de entorno requeridas

```env
SECRET_KEY=<min 32 chars>          # Requerida en producción
DATABASE_URL=postgresql://...       # PostgreSQL
REDIS_URL=redis://...               # Para rate limiting y cache
SENTRY_DSN=https://...             # Opcional, monitoreo
VIRUSTOTAL_API_KEY=...             # APIs de threat intel
ABUSEIPDB_API_KEY=...
# ... (ver app/config.py para la lista completa)
```
