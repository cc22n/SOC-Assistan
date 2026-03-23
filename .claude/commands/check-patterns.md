# /check-patterns — Verificar Patrones Prohibidos

Escanea TODO el código Python del proyecto buscando anti-patrones conocidos que deben estar eliminados.

## Instrucciones para el agente

Usa `Grep` para buscar cada patrón. Reporta TODOS los archivos y líneas donde aparezcan.

### Búsquedas a ejecutar

**1. `.query.get()` deprecado (debe ser `db.session.get()`)**
```
Patrón: \.query\.get\(
Excluir: .query.get_or_404  (este es válido)
Archivos: app/**/*.py
```

**2. Bare except sin logging**
```
Patrón: except:\s*\n\s*pass
Archivos: app/**/*.py
```

**3. `str(e)` expuesto en JSON**
```
Patrón: jsonify.*str\(e\)
Archivos: app/**/*.py
```

**4. `contains()` sin autoescape**
```
Patrón: \.contains\([^)]*\)
Buscar que NO tengan autoescape=True
Archivos: app/**/*.py
```

**5. Rutas sensibles sin `@login_required`**
```
Patrón: @.*_bp\.route\('/(analyze|history|incidents|dashboard|chat|api-stats|search)
Verificar que la siguiente línea sea @login_required
Archivos: app/routes/**/*.py
```

**6. Acceso a incidentes sin verificar ownership**
```
Patrón: db\.session\.get\(Incident
Verificar que haya _check_incident_access() o equivalente después
Archivos: app/routes/incident_routes.py
```

**7. Info disclosure en producción**
```
Patrón: 'error':\s*str\(e\)
Archivos: app/**/*.py
```

## Resultado esperado

```
✅ PATRÓN LIMPIO: .query.get() deprecado — 0 ocurrencias
✅ PATRÓN LIMPIO: bare except — 0 ocurrencias
⚠️  PROBLEMA: str(e) expuesto — 2 ocurrencias en app/routes/api_v2_routes.py:45, :89
...
```

**Score de limpieza**: X/7 patrones limpios

Si hay problemas, propón el fix inmediato o abre un issue en `BITACORA.md`.
