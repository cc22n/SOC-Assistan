# /complete-task — Marcar Tarea como Completada

Marca una tarea del plan como completada y actualiza la bitácora.

## Uso
```
/complete-task T3A-01
```

## Instrucciones para el agente

1. **Recibe** el ID de tarea como argumento (ej: `T3A-01`, `T4B-02`)
2. **Lee** `PLAN-MEJORAS.md`
3. **Encuentra** la línea con ese ID (ej: `- [ ] **T3A-01**`)
4. **Cambia** `- [ ]` por `- [x]` en esa línea
5. **Actualiza** la tabla de progreso al final del archivo:
   - Incrementa "Completadas" en la fase correspondiente
   - Recalcula el porcentaje
6. **Lee** `BITACORA.md` y agrega la tarea completada en la sección de la fase actual

## Formato de confirmación

```
✅ Tarea T3A-01 marcada como completada en PLAN-MEJORAS.md

Progreso Fase 3: 1/14 (7%)
Próxima tarea sugerida: T3A-02 — tests/test_auth.py

BITACORA.md actualizada.
```

## Notas
- Solo marcar como completada si el código realmente funciona y los tests pasan
- Si la tarea tiene subtareas, todas deben estar implementadas
