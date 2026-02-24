-- ============================================================================
-- MIGRACIÓN: Agregar APIs v3.1 (Censys, IPinfo)
-- SOC Agent - v3.1
-- Fecha: 2026-02-16
-- ============================================================================

BEGIN;

-- ============================================================================
-- NUEVAS COLUMNAS EN ioc_analyses
-- ============================================================================

-- Censys Platform API v3 (escaneo de hosts, certificados, puertos)
ALTER TABLE ioc_analyses 
ADD COLUMN IF NOT EXISTS censys_data JSONB;

-- IPinfo.io Lite (geolocalización, ASN, empresa, privacidad)
ALTER TABLE ioc_analyses 
ADD COLUMN IF NOT EXISTS ipinfo_data JSONB;

-- ============================================================================
-- ÍNDICES GIN para búsquedas en JSONB (opcional pero recomendado)
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_censys_data 
ON ioc_analyses USING gin (censys_data) 
WHERE censys_data IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_ipinfo_data 
ON ioc_analyses USING gin (ipinfo_data) 
WHERE ipinfo_data IS NOT NULL;

-- ============================================================================
-- VERIFICACIÓN
-- ============================================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'ioc_analyses' AND column_name = 'censys_data'
    ) THEN
        RAISE EXCEPTION 'Columna censys_data no fue creada';
    END IF;
    
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'ioc_analyses' AND column_name = 'ipinfo_data'
    ) THEN
        RAISE EXCEPTION 'Columna ipinfo_data no fue creada';
    END IF;
    
    RAISE NOTICE '✅ Migración v3.1 completada exitosamente';
    RAISE NOTICE '   - censys_data: OK';
    RAISE NOTICE '   - ipinfo_data: OK';
    RAISE NOTICE '   - Índices GIN: OK';
END $$;

COMMIT;

-- ============================================================================
-- INSTRUCCIONES DE USO
-- ============================================================================
-- 
-- Para ejecutar:
--   psql -U soc_admin -d soc_agent -f add_apis_v31_censys_ipinfo.sql
--
-- Para revertir:
--   ALTER TABLE ioc_analyses DROP COLUMN IF EXISTS censys_data;
--   ALTER TABLE ioc_analyses DROP COLUMN IF EXISTS ipinfo_data;
--   DROP INDEX IF EXISTS idx_censys_data;
--   DROP INDEX IF EXISTS idx_ipinfo_data;
--
-- ============================================================================
