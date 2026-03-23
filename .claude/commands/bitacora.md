# /bitacora — Actualizar Bitácora de Cambios

Actualiza `BITACORA.md` con los cambios realizados en la sesión actual.

## Instrucciones para el agente

1. **Lee primero** `BITACORA.md` para ver el estado actual
2. **Determina el número de fase actual** mirando la última entrada
3. **Recopila los cambios de esta sesión**:
   - Archivos modificados (usa `git diff --stat` o recuerda los cambios hechos)
   - Bugs corregidos
   - Features añadidas
   - Vulnerabilidades parcheadas
4. **Añade una nueva entrada** al inicio de la sección "## Historial de Fases" en `BITACORA.md`

## Formato de entrada a añadir

```markdown
---

### 📅 FASE X — [YYYY-MM-DD]
**Agente**: Claude [versión si conocida]
**Calificación inicio**: X.X/10
**Calificación fin**: X.X/10

#### ✅ Cambios Realizados
- [ archivo ] descripción del cambio
- [ archivo ] descripción del cambio

#### 🐛 Bugs Corregidos
- [BUG-ID] Descripción breve del fix

#### 🔒 Seguridad
- Vulnerabilidades parcheadas (si aplica)

#### 📌 Pendiente para Siguiente Fase
- Tarea pendiente 1
- Tarea pendiente 2
```

5. **Verifica** que el archivo quedó bien formateado
6. **Confirma** al usuario que la bitácora fue actualizada
