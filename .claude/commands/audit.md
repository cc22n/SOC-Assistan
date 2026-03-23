# /audit — Auditoría de Seguridad y Bugs

Ejecuta una auditoría completa del proyecto SOC Agent. Analiza todos los archivos Python en `app/` y produce un reporte estructurado.

## Instrucciones para el agente

Lee los siguientes archivos clave y analiza cada uno:

```
app/__init__.py
app/config.py
app/models/ioc.py
app/models/user.py
app/routes/auth.py
app/routes/main.py
app/routes/api_v2_routes.py
app/routes/incident_routes.py
app/services/llm_orchestrator.py
app/services/threat_intel.py
app/schemas/api.py
app/docs/openapi.py
```

## Estructura del reporte

Produce un reporte con estas 4 secciones:

### 1. 🐛 BUGS CRÍTICOS
Bugs que causan crashes, datos incorrectos o comportamiento inesperado.
- Formato: `[BUG-XX] Archivo:línea — Descripción — Impacto — Fix sugerido`

### 2. 🔒 VULNERABILIDADES DE SEGURIDAD
Problemas de seguridad explotables.
- Categorías: IDOR, inyección, auth bypass, info disclosure, CSRF, open redirect
- Formato: `[SEC-XX] Severidad: CRÍTICA/ALTA/MEDIA — Archivo:línea — Descripción`

### 3. ⚠️ PATRONES PROHIBIDOS DETECTADOS
Busca específicamente estos anti-patrones del proyecto:
- `Model.query.get(id)` — usar `db.session.get(Model, id)`
- `except: pass` o `bare except` sin logging
- `str(e)` expuesto en respuestas JSON de producción
- `@login_required` faltante en rutas sensibles
- `.query.get()` en lugar de `.query.get_or_404()` donde aplique
- Acceso a recursos sin verificar `created_by` o `assigned_to`
- `contains()` sin `autoescape=True` en búsquedas de texto

### 4. 📊 CALIFICACIÓN
Score de 0-10 basado en:
- Seguridad (40%): autenticación, autorización, sanitización
- Calidad de código (30%): patrones correctos, manejo de errores
- Robustez (20%): validaciones, edge cases
- Arquitectura (10%): separación de concerns, escalabilidad

**Al finalizar**: Si encuentras bugs nuevos, actualiza `BITACORA.md` con los hallazgos usando la sección "Bugs Detectados en Sesión".
