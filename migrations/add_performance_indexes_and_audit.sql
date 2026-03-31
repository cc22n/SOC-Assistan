-- ============================================================================
-- Migración: Índices de performance + tabla audit_events
-- Fase 4 - T4B-03 + T4A-02
-- Ejecutar en PostgreSQL: psql -d soc_agent -f add_performance_indexes_and_audit.sql
-- ============================================================================

-- ============================================================================
-- TABLA AUDIT EVENTS (inmutable, append-only)
-- ============================================================================
CREATE TABLE IF NOT EXISTS audit_events (
    id              SERIAL PRIMARY KEY,
    user_id         INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username        VARCHAR(80),
    action          VARCHAR(80) NOT NULL,
    resource_type   VARCHAR(50),
    resource_id     INTEGER,
    details         JSONB,
    ip_address      VARCHAR(45),
    user_agent      VARCHAR(300),
    request_id      VARCHAR(36),
    success         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Índices para audit_events
CREATE INDEX IF NOT EXISTS ix_audit_user_created    ON audit_events (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_audit_action_created  ON audit_events (action, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_audit_resource        ON audit_events (resource_type, resource_id);
CREATE INDEX IF NOT EXISTS ix_audit_success         ON audit_events (success, created_at DESC)
    WHERE success = FALSE;  -- Partial index: solo fallos (más pequeño y rápido para alertas)

-- Comentario descriptivo
COMMENT ON TABLE audit_events IS 'Registro de auditoría inmutable. Solo INSERT, nunca UPDATE/DELETE.';

-- ============================================================================
-- ÍNDICES COMPUESTOS EN ioc_analyses
-- ============================================================================

-- (user_id, created_at DESC) — para "mis análisis recientes"
CREATE INDEX IF NOT EXISTS ix_ioc_analyses_user_created
    ON ioc_analyses (user_id, created_at DESC);

-- (ioc_id, created_at DESC) — para "análisis de un IOC ordenados por fecha"
CREATE INDEX IF NOT EXISTS ix_ioc_analyses_ioc_created
    ON ioc_analyses (ioc_id, created_at DESC);

-- (risk_level, created_at DESC) — para dashboard de IOCs críticos recientes
CREATE INDEX IF NOT EXISTS ix_ioc_analyses_risk_created
    ON ioc_analyses (risk_level, created_at DESC);

-- ============================================================================
-- ÍNDICES COMPUESTOS EN incidents
-- ============================================================================

-- (status, created_at DESC) — para listar incidentes abiertos recientes
CREATE INDEX IF NOT EXISTS ix_incidents_status_created
    ON incidents (status, created_at DESC);

-- (created_by, created_at DESC) — para "mis incidentes"
CREATE INDEX IF NOT EXISTS ix_incidents_creator_created
    ON incidents (created_by, created_at DESC);

-- (assigned_to, status) — para "mis asignaciones abiertas"
CREATE INDEX IF NOT EXISTS ix_incidents_assignee_status
    ON incidents (assigned_to, status)
    WHERE assigned_to IS NOT NULL;

-- ============================================================================
-- ÍNDICES EN api_usage (verificar si ya existen)
-- ============================================================================

-- (api_name, date) — para tracking diario por API
CREATE INDEX IF NOT EXISTS ix_api_usage_name_date
    ON api_usage (api_name, date DESC);

-- ============================================================================
-- ÍNDICE GIN EN audit_events.details para búsquedas JSONB
-- ============================================================================
CREATE INDEX IF NOT EXISTS ix_audit_details_gin
    ON audit_events USING GIN (details);

SELECT 'Migration completed successfully' AS status;
