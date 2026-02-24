-- ============================================================================
-- MIGRACIÓN: Sistema de Sesiones de Investigación
-- SOC Agent - Fase 1.5
-- Fecha: 2024-02-01
-- ============================================================================

-- Descripción:
-- Este script crea las tablas necesarias para mantener contexto entre mensajes
-- del chat, permitiendo investigaciones multi-IOC con historial persistente.
SET client_encoding = 'UTF8';
BEGIN;

-- ============================================================================
-- TABLA: investigation_sessions
-- Sesiones de investigación que agrupan IOCs y mensajes
-- ============================================================================

CREATE TABLE IF NOT EXISTS investigation_sessions (
    id SERIAL PRIMARY KEY,
    uuid UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Metadatos
    title VARCHAR(200),
    description TEXT,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'paused', 'closed', 'archived')),
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    closed_at TIMESTAMP WITH TIME ZONE,
    last_activity_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Estadísticas (actualizadas por triggers)
    total_iocs INTEGER DEFAULT 0,
    total_messages INTEGER DEFAULT 0,
    highest_risk_level VARCHAR(20),
    
    -- Resumen comprimido para contexto LLM eficiente
    compressed_summary TEXT,
    summary_updated_at TIMESTAMP WITH TIME ZONE,
    
    -- Vinculación con incidentes
    incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    
    -- Configuración
    auto_close_hours INTEGER DEFAULT 24,
    
    -- LLM preferido para esta sesión
    preferred_llm_provider VARCHAR(20)
);

-- Comentarios de columnas
COMMENT ON TABLE investigation_sessions IS 'Sesiones de investigación que agrupan IOCs y mensajes de chat';
COMMENT ON COLUMN investigation_sessions.compressed_summary IS 'Resumen generado por LLM de mensajes antiguos para mantener contexto sin enviar todo el historial';
COMMENT ON COLUMN investigation_sessions.auto_close_hours IS 'Horas de inactividad antes de cerrar automáticamente (default 24h)';

-- ============================================================================
-- TABLA: session_iocs
-- IOCs vinculados a una sesión de investigación
-- ============================================================================

CREATE TABLE IF NOT EXISTS session_iocs (
    id SERIAL PRIMARY KEY,
    session_id INTEGER NOT NULL REFERENCES investigation_sessions(id) ON DELETE CASCADE,
    ioc_id INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    analysis_id INTEGER REFERENCES ioc_analyses(id) ON DELETE SET NULL,
    
    -- Contexto dentro de la sesión
    role VARCHAR(20) DEFAULT 'analyzed' CHECK (role IN ('primary', 'related', 'context', 'analyzed')),
    added_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    added_by_message_id INTEGER,
    
    -- Notas del analista
    analyst_notes TEXT,
    
    -- Relaciones con otros IOCs en la sesión
    related_to_ioc_ids INTEGER[],
    relationship_type VARCHAR(50),
    
    -- Constraint único: un IOC solo puede estar una vez por sesión
    UNIQUE(session_id, ioc_id)
);

COMMENT ON TABLE session_iocs IS 'Vincula IOCs analizados a sesiones de investigación';
COMMENT ON COLUMN session_iocs.role IS 'Rol del IOC: primary (principal), related (relacionado), context (contexto), analyzed (analizado)';
COMMENT ON COLUMN session_iocs.relationship_type IS 'Tipo de relación: same_campaign, c2_connection, dropped_by, downloads_from, etc.';

-- ============================================================================
-- TABLA: session_messages
-- Mensajes del chat dentro de una sesión
-- ============================================================================

CREATE TABLE IF NOT EXISTS session_messages (
    id SERIAL PRIMARY KEY,
    session_id INTEGER NOT NULL REFERENCES investigation_sessions(id) ON DELETE CASCADE,
    
    -- Contenido
    role VARCHAR(20) NOT NULL CHECK (role IN ('user', 'assistant', 'system')),
    content TEXT NOT NULL,
    
    -- Metadatos
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Referencias a IOCs mencionados
    iocs_mentioned TEXT[],
    
    -- Si este mensaje disparó un análisis
    analysis_triggered BOOLEAN DEFAULT FALSE,
    analysis_id INTEGER REFERENCES ioc_analyses(id) ON DELETE SET NULL,
    
    -- Para manejo eficiente de contexto
    is_summary BOOLEAN DEFAULT FALSE,
    tokens_estimated INTEGER,
    
    -- LLM que generó la respuesta (solo para role='assistant')
    llm_provider VARCHAR(20)
);

COMMENT ON TABLE session_messages IS 'Historial de mensajes del chat por sesión';
COMMENT ON COLUMN session_messages.is_summary IS 'True si es un mensaje de resumen comprimido generado automáticamente';
COMMENT ON COLUMN session_messages.tokens_estimated IS 'Estimación de tokens para control de contexto';

-- ============================================================================
-- ÍNDICES
-- ============================================================================

-- Índices para investigation_sessions
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON investigation_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON investigation_sessions(status);
CREATE INDEX IF NOT EXISTS idx_sessions_user_active ON investigation_sessions(user_id, status) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_sessions_last_activity ON investigation_sessions(last_activity_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_created_at ON investigation_sessions(created_at DESC);

-- Índices para session_iocs
CREATE INDEX IF NOT EXISTS idx_session_iocs_session ON session_iocs(session_id);
CREATE INDEX IF NOT EXISTS idx_session_iocs_ioc ON session_iocs(ioc_id);
CREATE INDEX IF NOT EXISTS idx_session_iocs_analysis ON session_iocs(analysis_id);

-- Índices para session_messages
CREATE INDEX IF NOT EXISTS idx_session_messages_session ON session_messages(session_id);
CREATE INDEX IF NOT EXISTS idx_session_messages_session_created ON session_messages(session_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_session_messages_analysis ON session_messages(analysis_id) WHERE analysis_id IS NOT NULL;

-- ============================================================================
-- TRIGGERS
-- ============================================================================

-- Función para actualizar updated_at automáticamente
CREATE OR REPLACE FUNCTION update_session_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger para updated_at en investigation_sessions
DROP TRIGGER IF EXISTS trigger_session_updated_at ON investigation_sessions;
CREATE TRIGGER trigger_session_updated_at
    BEFORE UPDATE ON investigation_sessions
    FOR EACH ROW
    EXECUTE FUNCTION update_session_updated_at();

-- Función para actualizar estadísticas de sesión cuando se agrega IOC
CREATE OR REPLACE FUNCTION update_session_ioc_stats()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE investigation_sessions 
        SET total_iocs = total_iocs + 1,
            last_activity_at = NOW()
        WHERE id = NEW.session_id;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE investigation_sessions 
        SET total_iocs = total_iocs - 1
        WHERE id = OLD.session_id;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Trigger para estadísticas de IOCs
DROP TRIGGER IF EXISTS trigger_session_ioc_stats ON session_iocs;
CREATE TRIGGER trigger_session_ioc_stats
    AFTER INSERT OR DELETE ON session_iocs
    FOR EACH ROW
    EXECUTE FUNCTION update_session_ioc_stats();

-- Función para actualizar estadísticas de sesión cuando se agrega mensaje
CREATE OR REPLACE FUNCTION update_session_message_stats()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE investigation_sessions 
        SET total_messages = total_messages + 1,
            last_activity_at = NOW()
        WHERE id = NEW.session_id;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE investigation_sessions 
        SET total_messages = total_messages - 1
        WHERE id = OLD.session_id;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Trigger para estadísticas de mensajes
DROP TRIGGER IF EXISTS trigger_session_message_stats ON session_messages;
CREATE TRIGGER trigger_session_message_stats
    AFTER INSERT OR DELETE ON session_messages
    FOR EACH ROW
    EXECUTE FUNCTION update_session_message_stats();

-- Función para actualizar highest_risk_level cuando se agrega IOC
CREATE OR REPLACE FUNCTION update_session_risk_level()
RETURNS TRIGGER AS $$
DECLARE
    max_risk VARCHAR(20);
    risk_priority INTEGER;
BEGIN
    -- Obtener el nivel de riesgo más alto de los análisis en la sesión
    SELECT 
        CASE 
            WHEN EXISTS (SELECT 1 FROM session_iocs si 
                        JOIN ioc_analyses ia ON si.analysis_id = ia.id 
                        WHERE si.session_id = NEW.session_id AND ia.risk_level = 'CRÍTICO') THEN 'CRÍTICO'
            WHEN EXISTS (SELECT 1 FROM session_iocs si 
                        JOIN ioc_analyses ia ON si.analysis_id = ia.id 
                        WHERE si.session_id = NEW.session_id AND ia.risk_level = 'ALTO') THEN 'ALTO'
            WHEN EXISTS (SELECT 1 FROM session_iocs si 
                        JOIN ioc_analyses ia ON si.analysis_id = ia.id 
                        WHERE si.session_id = NEW.session_id AND ia.risk_level = 'MEDIO') THEN 'MEDIO'
            WHEN EXISTS (SELECT 1 FROM session_iocs si 
                        JOIN ioc_analyses ia ON si.analysis_id = ia.id 
                        WHERE si.session_id = NEW.session_id AND ia.risk_level = 'BAJO') THEN 'BAJO'
            ELSE 'LIMPIO'
        END INTO max_risk;
    
    UPDATE investigation_sessions 
    SET highest_risk_level = max_risk
    WHERE id = NEW.session_id;
    
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Trigger para actualizar risk level
DROP TRIGGER IF EXISTS trigger_session_risk_level ON session_iocs;
CREATE TRIGGER trigger_session_risk_level
    AFTER INSERT OR UPDATE ON session_iocs
    FOR EACH ROW
    WHEN (NEW.analysis_id IS NOT NULL)
    EXECUTE FUNCTION update_session_risk_level();

-- ============================================================================
-- FUNCIÓN: Auto-cerrar sesiones inactivas
-- Ejecutar periódicamente con pg_cron o Celery
-- ============================================================================

CREATE OR REPLACE FUNCTION auto_close_inactive_sessions()
RETURNS INTEGER AS $$
DECLARE
    closed_count INTEGER;
BEGIN
    WITH closed AS (
        UPDATE investigation_sessions
        SET status = 'closed',
            closed_at = NOW()
        WHERE status = 'active'
          AND last_activity_at < NOW() - (auto_close_hours || ' hours')::INTERVAL
        RETURNING id
    )
    SELECT COUNT(*) INTO closed_count FROM closed;
    
    RETURN closed_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION auto_close_inactive_sessions IS 'Cierra sesiones inactivas según su configuración auto_close_hours. Ejecutar periódicamente.';

-- ============================================================================
-- VISTAS ÚTILES
-- ============================================================================

-- Vista: Sesiones activas con resumen
CREATE OR REPLACE VIEW v_active_sessions AS
SELECT 
    s.id,
    s.uuid,
    s.user_id,
    u.username,
    s.title,
    s.status,
    s.total_iocs,
    s.total_messages,
    s.highest_risk_level,
    s.created_at,
    s.last_activity_at,
    EXTRACT(EPOCH FROM (NOW() - s.last_activity_at))/3600 AS hours_inactive,
    s.auto_close_hours - EXTRACT(EPOCH FROM (NOW() - s.last_activity_at))/3600 AS hours_until_auto_close
FROM investigation_sessions s
JOIN users u ON s.user_id = u.id
WHERE s.status = 'active';

COMMENT ON VIEW v_active_sessions IS 'Sesiones activas con información de usuario y tiempo restante';

-- Vista: IOCs por sesión con análisis
CREATE OR REPLACE VIEW v_session_iocs_detail AS
SELECT 
    si.session_id,
    si.ioc_id,
    i.value AS ioc_value,
    i.ioc_type,
    si.role,
    si.added_at,
    si.analyst_notes,
    ia.confidence_score,
    ia.risk_level,
    ia.created_at AS analysis_date
FROM session_iocs si
JOIN iocs i ON si.ioc_id = i.id
LEFT JOIN ioc_analyses ia ON si.analysis_id = ia.id;

COMMENT ON VIEW v_session_iocs_detail IS 'Detalle de IOCs por sesión con información de análisis';

-- ============================================================================
-- DATOS INICIALES (opcional)
-- ============================================================================

-- No hay datos iniciales necesarios para las tablas de sesiones

-- ============================================================================
-- VERIFICACIÓN
-- ============================================================================

DO $$
BEGIN
    -- Verificar que las tablas existen
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'investigation_sessions') THEN
        RAISE EXCEPTION 'Tabla investigation_sessions no fue creada';
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'session_iocs') THEN
        RAISE EXCEPTION 'Tabla session_iocs no fue creada';
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'session_messages') THEN
        RAISE EXCEPTION 'Tabla session_messages no fue creada';
    END IF;
    
    RAISE NOTICE ' Migración completada exitosamente';
    RAISE NOTICE '   - investigation_sessions: OK';
    RAISE NOTICE '   - session_iocs: OK';
    RAISE NOTICE '   - session_messages: OK';
    RAISE NOTICE '   - Triggers: OK';
    RAISE NOTICE '   - Vistas: OK';
END $$;

COMMIT;

-- ============================================================================
-- INSTRUCCIONES DE USO
-- ============================================================================
-- 
-- Para ejecutar esta migración:
--   psql -U soc_admin -d soc_agent -f add_investigation_sessions.sql
--
-- Para revertir (¡CUIDADO! Borra todos los datos de sesiones):
--   DROP TABLE IF EXISTS session_messages CASCADE;
--   DROP TABLE IF EXISTS session_iocs CASCADE;
--   DROP TABLE IF EXISTS investigation_sessions CASCADE;
--   DROP VIEW IF EXISTS v_active_sessions;
--   DROP VIEW IF EXISTS v_session_iocs_detail;
--   DROP FUNCTION IF EXISTS update_session_updated_at;
--   DROP FUNCTION IF EXISTS update_session_ioc_stats;
--   DROP FUNCTION IF EXISTS update_session_message_stats;
--   DROP FUNCTION IF EXISTS update_session_risk_level;
--   DROP FUNCTION IF EXISTS auto_close_inactive_sessions;
--
-- ============================================================================
