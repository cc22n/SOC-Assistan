# SQL legacy (pre-Alembic)

Los `.sql` en esta carpeta (`add_apis_v31_censys_ipinfo.sql`, `add_incidents_v31.sql`,
`add_investigation_sessions.sql`, `add_new_api_fields_v3.sql`,
`add_performance_indexes_and_audit.sql`) documentan `ALTER TABLE` manuales
aplicados antes de adoptar Alembic. **Ya no se ejecutan desde ningún lado**
(ni `docker/init_db.py`, ni CI, ni los tests) — se conservan solo como
historial. Los cambios de esquema de aquí en adelante van en
`migrations/versions/` (ver sección "Base de datos" en `CLAUDE.md`).

Nota sobre `add_investigation_sessions.sql`: define 4 triggers SQL
(`trigger_session_ioc_stats`, `trigger_session_message_stats`,
`trigger_session_risk_level`, `trigger_session_updated_at`) que debían
mantener `total_iocs`/`total_messages`/`highest_risk_level` de
`InvestigationSession`. Ese archivo nunca se ejecutó en ningún ambiente real
(dev/test/CI), así que esos triggers nunca existieron fuera de este `.sql`.
La migración base de Alembic **no los incluye a propósito**: esos contadores
ahora los mantiene `SessionManager` en Python (`add_ioc_to_session`,
`save_message`), no triggers de BD. Las 2 vistas (`v_active_sessions`,
`v_session_iocs_detail`) y `auto_close_inactive_sessions()` del mismo archivo
tampoco se migran — no tienen ninguna referencia en el código de la app.
