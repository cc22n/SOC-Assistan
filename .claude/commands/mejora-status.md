# /mejora-status — Estado del Plan de Mejoras

Muestra el estado actual del plan de mejoras del proyecto SOC Agent.

## Instrucciones para el agente

1. **Lee** `PLAN-MEJORAS.md` completo
2. **Cuenta** las tareas completadas (`[x]`) vs pendientes (`[ ]`) por fase
3. **Lee** `AGENTE_CONTEXTO.md` para el score actual
4. **Calcula** el progreso estimado hacia el score objetivo

## Formato de salida

```
╔══════════════════════════════════════════╗
║     SOC Agent — Estado de Mejoras        ║
╚══════════════════════════════════════════╝

📊 Score: X.X/10 → Objetivo: 9.5/10

FASE 3 [En curso]  ████░░░░░░  X/14 tareas (XX%)
FASE 4 [Pendiente] ░░░░░░░░░░  0/8 tareas
FASE 5 [Pendiente] ░░░░░░░░░░  0/7 tareas

✅ Completadas esta sesión:
  - T3A-01: conftest.py con fixtures base
  - ...

🔜 Próxima tarea: T3A-0X — [descripción]

⚠️  Bloqueantes:
  - [Cualquier dependencia no resuelta]
```

5. **Sugiere** la próxima tarea a ejecutar según el orden del plan
6. **Alerta** si hay tareas en Fase 4 o 5 iniciadas sin completar Fase 3
