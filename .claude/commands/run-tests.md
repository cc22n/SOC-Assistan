# /run-tests — Ejecutar Tests y Reportar Cobertura

Ejecuta la suite de tests del proyecto y reporta los resultados con análisis.

## Instrucciones para el agente

1. **Verifica** que el entorno virtual está activo (busca `venv/` o `.venv/`)
2. **Ejecuta los tests en este orden**:

```bash
# Tests de sprint anteriores (no deben romperse)
pytest sprint2_tests/tests/ -v --tb=short 2>&1

# Tests de Pydantic
pytest sprint3_pydantic/tests/ -v --tb=short 2>&1

# Tests nuevos con cobertura
pytest tests/ -v --cov=app --cov-report=term-missing --tb=short 2>&1
```

3. **Analiza los resultados**:
   - ¿Cuántos tests pasaron / fallaron / fueron skipped?
   - ¿Cuál es el % de cobertura por módulo?
   - ¿Qué líneas críticas NO están cubiertas?

4. **Identifica tests faltantes** según `PLAN-MEJORAS.md` sección T3A

5. **Produce el reporte en este formato**:

```
╔══════════════════════════════════════════╗
║         SOC Agent — Test Report          ║
╚══════════════════════════════════════════╝

Sprint 2:  XX passed, X failed  (sprint2_tests/)
Sprint 3:  XX passed, X failed  (sprint3_pydantic/)
Main:      XX passed, X failed  (tests/)

Cobertura total: XX%  [objetivo: 60%]

Por módulo:
  app/routes/auth.py          XX%  ██████░░░░
  app/routes/incident_routes  XX%  ████░░░░░░
  app/services/threat_intel   XX%  ██░░░░░░░░

❌ Tests fallando:
  - test_name: motivo del fallo

⚠️ Módulos sin cobertura (0%):
  - app/services/...

✅ Próximo paso: crear tests para [módulo más crítico sin cobertura]
```

6. **Si hay tests fallando**, analiza el error y propone un fix antes de continuar con nuevas tareas.

## Notas importantes
- Si `pytest` no está instalado: `pip install pytest pytest-cov`
- Si la DB no existe para tests: verificar que `TESTING=True` en el entorno usa SQLite o DB de test
- No modificar tests existentes que pasan — solo agregar nuevos
