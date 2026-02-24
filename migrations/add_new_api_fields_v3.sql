-- ==============================================================================
-- SOC Agent - Migración v3.0
-- Agregar campos para nuevas APIs de Threat Intelligence
-- Febrero 2025
--
-- EJECUTAR: psql -U soc_admin -d soc_agent -f add_new_api_fields.sql
-- ==============================================================================

-- Inicio de transacción
BEGIN;

-- ==============================================================================
-- 1. Agregar nuevos campos a ioc_analyses
-- ==============================================================================

-- Campos que ya deberían existir (verificar primero)
DO $$
BEGIN
    -- greynoise_data
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'ioc_analyses' AND column_name = 'greynoise_data') THEN
        ALTER TABLE ioc_analyses ADD COLUMN greynoise_data JSONB;
        RAISE NOTICE 'Agregado: greynoise_data';
    END IF;

    -- urlhaus_data
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'ioc_analyses' AND column_name = 'urlhaus_data') THEN
        ALTER TABLE ioc_analyses ADD COLUMN urlhaus_data JSONB;
        RAISE NOTICE 'Agregado: urlhaus_data';
    END IF;

    -- threatfox_data
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'ioc_analyses' AND column_name = 'threatfox_data') THEN
        ALTER TABLE ioc_analyses ADD COLUMN threatfox_data JSONB;
        RAISE NOTICE 'Agregado: threatfox_data';
    END IF;

    -- google_safebrowsing_data
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'ioc_analyses' AND column_name = 'google_safebrowsing_data') THEN
        ALTER TABLE ioc_analyses ADD COLUMN google_safebrowsing_data JSONB;
        RAISE NOTICE 'Agregado: google_safebrowsing_data';
    END IF;

    -- securitytrails_data
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'ioc_analyses' AND column_name = 'securitytrails_data') THEN
        ALTER TABLE ioc_analyses ADD COLUMN securitytrails_data JSONB;
        RAISE NOTICE 'Agregado: securitytrails_data';
    END IF;

    -- hybrid_analysis_data
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'ioc_analyses' AND column_name = 'hybrid_analysis_data') THEN
        ALTER TABLE ioc_analyses ADD COLUMN hybrid_analysis_data JSONB;
        RAISE NOTICE 'Agregado: hybrid_analysis_data';
    END IF;

    -- sources_used
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'ioc_analyses' AND column_name = 'sources_used') THEN
        ALTER TABLE ioc_analyses ADD COLUMN sources_used JSONB DEFAULT '[]'::jsonb;
        RAISE NOTICE 'Agregado: sources_used';
    END IF;

    -- ==============================================================================
    -- 2. NUEVOS CAMPOS v3.0
    -- ==============================================================================

    -- malwarebazaar_data (abuse.ch)
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'ioc_analyses' AND column_name = 'malwarebazaar_data') THEN
        ALTER TABLE ioc_analyses ADD COLUMN malwarebazaar_data JSONB;
        RAISE NOTICE 'Agregado: malwarebazaar_data';
    END IF;

    -- criminal_ip_data (NUEVO)
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'ioc_analyses' AND column_name = 'criminal_ip_data') THEN
        ALTER TABLE ioc_analyses ADD COLUMN criminal_ip_data JSONB;
        RAISE NOTICE 'Agregado: criminal_ip_data';
    END IF;

    -- pulsedive_data (NUEVO)
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'ioc_analyses' AND column_name = 'pulsedive_data') THEN
        ALTER TABLE ioc_analyses ADD COLUMN pulsedive_data JSONB;
        RAISE NOTICE 'Agregado: pulsedive_data';
    END IF;

    -- urlscan_data (NUEVO)
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'ioc_analyses' AND column_name = 'urlscan_data') THEN
        ALTER TABLE ioc_analyses ADD COLUMN urlscan_data JSONB;
        RAISE NOTICE 'Agregado: urlscan_data';
    END IF;

    -- shodan_internetdb_data (NUEVO - API gratuita)
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'ioc_analyses' AND column_name = 'shodan_internetdb_data') THEN
        ALTER TABLE ioc_analyses ADD COLUMN shodan_internetdb_data JSONB;
        RAISE NOTICE 'Agregado: shodan_internetdb_data';
    END IF;

    -- ip_api_data (NUEVO - geolocalización gratuita)
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'ioc_analyses' AND column_name = 'ip_api_data') THEN
        ALTER TABLE ioc_analyses ADD COLUMN ip_api_data JSONB;
        RAISE NOTICE 'Agregado: ip_api_data';
    END IF;

END $$;

-- ==============================================================================
-- 3. Crear índices GIN para búsquedas en JSONB (opcional pero recomendado)
-- ==============================================================================

-- Índice para criminal_ip_data
CREATE INDEX IF NOT EXISTS idx_criminal_ip_data 
ON ioc_analyses USING gin (criminal_ip_data);

-- Índice para pulsedive_data
CREATE INDEX IF NOT EXISTS idx_pulsedive_data 
ON ioc_analyses USING gin (pulsedive_data);

-- Índice para malwarebazaar_data
CREATE INDEX IF NOT EXISTS idx_malwarebazaar_data 
ON ioc_analyses USING gin (malwarebazaar_data);

-- ==============================================================================
-- 4. Actualizar api_usage para nuevas APIs
-- ==============================================================================

-- Insertar registros iniciales para nuevas APIs (si no existen)
INSERT INTO api_usage (api_name, date, requests_count, errors_count)
SELECT 'criminal_ip', CURRENT_DATE, 0, 0
WHERE NOT EXISTS (SELECT 1 FROM api_usage WHERE api_name = 'criminal_ip' AND date = CURRENT_DATE);

INSERT INTO api_usage (api_name, date, requests_count, errors_count)
SELECT 'pulsedive', CURRENT_DATE, 0, 0
WHERE NOT EXISTS (SELECT 1 FROM api_usage WHERE api_name = 'pulsedive' AND date = CURRENT_DATE);

INSERT INTO api_usage (api_name, date, requests_count, errors_count)
SELECT 'urlscan', CURRENT_DATE, 0, 0
WHERE NOT EXISTS (SELECT 1 FROM api_usage WHERE api_name = 'urlscan' AND date = CURRENT_DATE);

INSERT INTO api_usage (api_name, date, requests_count, errors_count)
SELECT 'malwarebazaar', CURRENT_DATE, 0, 0
WHERE NOT EXISTS (SELECT 1 FROM api_usage WHERE api_name = 'malwarebazaar' AND date = CURRENT_DATE);

INSERT INTO api_usage (api_name, date, requests_count, errors_count)
SELECT 'shodan_internetdb', CURRENT_DATE, 0, 0
WHERE NOT EXISTS (SELECT 1 FROM api_usage WHERE api_name = 'shodan_internetdb' AND date = CURRENT_DATE);

INSERT INTO api_usage (api_name, date, requests_count, errors_count)
SELECT 'ip_api', CURRENT_DATE, 0, 0
WHERE NOT EXISTS (SELECT 1 FROM api_usage WHERE api_name = 'ip_api' AND date = CURRENT_DATE);

-- Commit de transacción
COMMIT;

-- ==============================================================================
-- 5. Verificación final
-- ==============================================================================

-- Mostrar estructura actual de ioc_analyses
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'ioc_analyses' 
AND column_name LIKE '%_data'
ORDER BY column_name;

-- Mostrar conteo de análisis por API
SELECT 
    'virustotal' as api, COUNT(*) FILTER (WHERE virustotal_data IS NOT NULL) as count
FROM ioc_analyses
UNION ALL
SELECT 'abuseipdb', COUNT(*) FILTER (WHERE abuseipdb_data IS NOT NULL) FROM ioc_analyses
UNION ALL
SELECT 'criminal_ip', COUNT(*) FILTER (WHERE criminal_ip_data IS NOT NULL) FROM ioc_analyses
UNION ALL
SELECT 'pulsedive', COUNT(*) FILTER (WHERE pulsedive_data IS NOT NULL) FROM ioc_analyses;

-- ==============================================================================
-- NOTAS:
-- 
-- Si necesitas revertir los cambios:
-- ALTER TABLE ioc_analyses DROP COLUMN IF EXISTS criminal_ip_data;
-- ALTER TABLE ioc_analyses DROP COLUMN IF EXISTS pulsedive_data;
-- ALTER TABLE ioc_analyses DROP COLUMN IF EXISTS urlscan_data;
-- ALTER TABLE ioc_analyses DROP COLUMN IF EXISTS malwarebazaar_data;
-- ALTER TABLE ioc_analyses DROP COLUMN IF EXISTS shodan_internetdb_data;
-- ALTER TABLE ioc_analyses DROP COLUMN IF EXISTS ip_api_data;
-- ==============================================================================
