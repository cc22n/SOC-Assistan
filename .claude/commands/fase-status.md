# /fase-status — Estado de la Fase Actual

Muestra un resumen ejecutivo del estado actual del proyecto SOC Agent.

## Instrucciones para el agente

### 1. Lee los archivos de contexto
- `AGENTE_CONTEXTO.md` — estado general del proyecto
- `BITACORA.md` — historial de cambios
- `ROADMAP_FASE3.md` — tareas pendientes

### 2. Ejecuta verificaciones rápidas

**Check de patrones prohibidos** (resumen de /check-patterns):
- Cuenta ocurrencias de anti-patrones principales

**Check de tests**:
- Verifica si existe `tests/` o `sprint2_tests/` con tests actualizados

**Check de TODOs pendientes**:
```
Busca: # TODO|# FIXME|# HACK|# XXX
en: app/**/*.py
```

### 3. Genera reporte de estado

```
╔══════════════════════════════════════╗
║     SOC AGENT — ESTADO DE FASE       ║
╠══════════════════════════════════════╣
║ Fase actual:      [N]                ║
║ Calificación:     [X.X]/10           ║
║ Objetivo:         8.0/10             ║
║ Progreso roadmap: [N]/[Total] tareas ║
╠══════════════════════════════════════╣
║ BUGS ABIERTOS:    [N]                ║
║ SEC. PENDIENTES:  [N]                ║
║ PATRONES MALOS:   [N]                ║
╠══════════════════════════════════════╣
║ PRÓXIMA ACCIÓN:                      ║
║ [descripción de la tarea más urgente]║
╚══════════════════════════════════════╝
```

### 4. Lista las 3 tareas más prioritarias para esta sesión

Basándote en `ROADMAP_FASE3.md`, indica:
1. **[URGENTE]** Tarea crítica que bloquea el score
2. **[IMPORTANTE]** Tarea que suma más puntos
3. **[RECOMENDADO]** Quick win para esta sesión
