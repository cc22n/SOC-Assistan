-- ============================================================================
-- MIGRACION: Sistema de Incidentes v3.1
-- SOC Agent - Mejoras de Incidentes
-- Fecha: 2026-02-20
-- ============================================================================

BEGIN;

-- ============================================================================
-- 1. Agregar session_id a incidents (vincular con investigacion)
-- ============================================================================

ALTER TABLE incidents 
ADD COLUMN IF NOT EXISTS session_id INTEGER REFERENCES investigation_sessions(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_incident_session ON incidents(session_id) WHERE session_id IS NOT NULL;

-- ============================================================================
-- 2. Tabla pivot: incident_iocs (multiples IOCs por incidente)
-- ============================================================================

CREATE TABLE IF NOT EXISTS incident_iocs (
    id SERIAL PRIMARY KEY,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    ioc_id INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    analysis_id INTEGER REFERENCES ioc_analyses(id) ON DELETE SET NULL,
    
    -- Contexto
    role VARCHAR(20) DEFAULT 'related' CHECK (role IN ('primary', 'related', 'context')),
    added_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    notes TEXT,
    
    UNIQUE(incident_id, ioc_id)
);

CREATE INDEX IF NOT EXISTS idx_incident_iocs_incident ON incident_iocs(incident_id);
CREATE INDEX IF NOT EXISTS idx_incident_iocs_ioc ON incident_iocs(ioc_id);

-- ============================================================================
-- VERIFICACION
-- ============================================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'incidents' AND column_name = 'session_id'
    ) THEN
        RAISE EXCEPTION 'Columna session_id no fue creada';
    END IF;
    
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables 
        WHERE table_name = 'incident_iocs'
    ) THEN
        RAISE EXCEPTION 'Tabla incident_iocs no fue creada';
    END IF;
    
    RAISE NOTICE 'Migracion v3.1 incidentes completada';
    RAISE NOTICE '   - incidents.session_id: OK';
    RAISE NOTICE '   - incident_iocs: OK';
END $$;

COMMIT;

-- Para ejecutar:
--   psql -U soc_admin -d soc_agent -f add_incidents_v31.sql
--
-- Para revertir:
--   DROP TABLE IF EXISTS incident_iocs;
--   ALTER TABLE incidents DROP COLUMN IF EXISTS session_id;
