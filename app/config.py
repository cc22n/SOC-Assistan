"""
SOC Agent - Configuración v3.0
Febrero 2025

CAMBIOS:
- NUEVAS: criminal_ip, pulsedive, urlscan
- ELIMINADAS: ipqualityscore, censys (problemáticas)
- Gemini usa nueva librería google-genai
"""
import os
from datetime import timedelta


class Config:
    """Configuración base"""

    # Flask
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-fallback-' + os.urandom(16).hex())
    # WP1: clave HMAC de la cadena de auditoría. Debe vivir FUERA de la BD y de sus copias de seguridad. Obligatoria en producción.
    AUDIT_CHAIN_KEY = os.environ.get('AUDIT_CHAIN_KEY') or None
    # Rotación: claves anteriores (coma) para seguir verificando lo ya sellado. ACCEPT_UNKEYED: la clave se añadió tarde y hay histórico sin clave.
    AUDIT_CHAIN_PREVIOUS_KEYS = os.environ.get('AUDIT_CHAIN_PREVIOUS_KEYS') or None
    AUDIT_CHAIN_ACCEPT_UNKEYED = os.environ.get('AUDIT_CHAIN_ACCEPT_UNKEYED') or None

    # Telegram (WP7): avisos SALIENTES de los feeds. Sin token no se hace nada. El token es un secreto: viaja en la URL de la API de
    # Telegram y aparece en el texto de cualquier excepción de red; app/services/telegram_client.py lo redacta siempre.
    TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN') or None
    # Lista (separada por comas) de chats permitidos que reciben los avisos. Solo se envía a estos; nunca a un chat arbitrario.
    TELEGRAM_ALERT_CHAT_IDS = tuple(int(x) for x in os.environ.get('TELEGRAM_ALERT_CHAT_IDS', '').replace(' ', '').split(',')
                                    if x.lstrip('-').isdigit())
    TELEGRAM_MIN_RISK = os.environ.get('TELEGRAM_MIN_RISK', 'ALTO').upper()       # ALTO | MEDIO | CRÍTICO
    TELEGRAM_BACKLOG_DAYS = int(os.environ.get('TELEGRAM_BACKLOG_DAYS', '3'))     # no avisar de CVE más antiguos al activarlo
    APP_BASE_URL = (os.environ.get('APP_BASE_URL') or '').rstrip('/')             # opcional: enlace "Analizar" en el aviso

    # Política de salida (WP4): dominios PROPIOS que deben tratarse como internos y no enviarse a APIs de terceros, separados
    # por coma (p. ej. "intranet.empresa.com,corp.empresa.com"). Casan por límite de etiqueta: "empresa.com" cubre
    # "a.empresa.com" pero no "noempresa.com". Los sufijos reservados (.local .lan .internal .corp...) ya están protegidos.
    EGRESS_INTERNAL_DOMAINS = tuple(d.strip().lower().strip('.') for d in
                                    os.environ.get('EGRESS_INTERNAL_DOMAINS', '').split(',') if d.strip().strip('.'))

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL',
                                             'postgresql://soc_admin:soc_password@localhost:5432/soc_agent')

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        # Sin timeouts, una BD caída o saturada dejaba a los workers colgados esperando
        # conexión indefinidamente. 3 workers x (5+10) = 45 conexiones máx. (< 100 de Postgres).
        'pool_size': 5,
        'max_overflow': 10,
        'pool_timeout': 10,                      # s esperando una conexión libre del pool
        'connect_args': {'connect_timeout': 5},  # s para establecer la conexión TCP/auth
    }

    # Redis
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')

    # Upload limits
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB

    # Session
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)

    # Zona horaria para mostrar fechas en templates renderizados server-side
    # (los timestamps se guardan en UTC naive vía app.utils.time_utils.utcnow())
    DISPLAY_TIMEZONE = os.environ.get('DISPLAY_TIMEZONE', 'America/Mexico_City')

    # ==========================================================================
    # Security - Cookies
    # ==========================================================================
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_DURATION = timedelta(days=7)

    # ==========================================================================
    # Security - CORS & Host Validation
    # ==========================================================================
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', 'http://127.0.0.1:5000,http://localhost:5000').split(',')
    ALLOWED_HOSTS = [h.strip() for h in os.environ.get('ALLOWED_HOSTS', '127.0.0.1,localhost').split(',') if h.strip()]

    # ==========================================================================
    # Observability & Monitoring
    # ==========================================================================
    SENTRY_DSN = os.environ.get('SENTRY_DSN')

    # ==========================================================================
    # API KEYS - Threat Intelligence
    # ==========================================================================
    API_KEYS = {
        # === APIs Principales ===
        'virustotal': os.environ.get('VIRUSTOTAL_API_KEY'),
        'abuseipdb': os.environ.get('ABUSEIPDB_API_KEY'),
        'shodan': os.environ.get('SHODAN_API_KEY'),
        'otx': os.environ.get('OTX_API_KEY'),
        'greynoise': os.environ.get('GREYNOISE_API_KEY'),
        'google_safebrowsing': os.environ.get('GOOGLE_SAFEBROWSING_API_KEY'),
        'securitytrails': os.environ.get('SECURITYTRAILS_API_KEY'),
        'hybrid_analysis': os.environ.get('HYBRID_ANALYSIS_API_KEY'),

        # === abuse.ch APIs (URLhaus, ThreatFox, MalwareBazaar) ===
        'abusech_auth': os.environ.get('ABUSECH_AUTH_KEY'),

        # === NUEVAS APIs ===
        'criminal_ip': os.environ.get('CRIMINAL_IP_API_KEY'),
        'pulsedive': os.environ.get('PULSEDIVE_API_KEY'),
        'urlscan': os.environ.get('URLSCAN_API_KEY'),

        # === APIs v3.1 ===
        'censys': os.environ.get('CENSYS_API_KEY'),
        'ipinfo': os.environ.get('IPINFO_TOKEN'),
        'ipgeolocation': os.environ.get('IPGEOLOCATION_API_KEY'),
        'nvd': os.environ.get('NVD_API_KEY'),   # OPCIONAL: sin clave 5 peticiones/30 s, con clave 50/30 s

        # === Búsqueda web (Deep Analysis) ===
        # Grafía canónica: TAVILY_API_KEY. Se acepta la grafía legacy
        # 'Tavily_API_KEY' por tolerancia con .env antiguos (en Linux
        # os.environ es case-sensitive).
        'tavily': os.environ.get('TAVILY_API_KEY') or os.environ.get('Tavily_API_KEY'),

        # === LLM Providers ===
        'xai': os.environ.get('XAI_API_KEY'),
        'openai': os.environ.get('OPENAI_API_KEY'),
        'deepseek': os.environ.get('DEEPSEEK_API_KEY'),
        'gemini': os.environ.get('GEMINI_API_KEY'),
        'kimi': os.environ.get('KIMI_API_KEY'),
    }

    # ==========================================================================
    # API Limits (requests per day)
    # ==========================================================================
    API_LIMITS = {
        'virustotal': 500,
        'abuseipdb': 1000,
        'shodan': 100,
        'otx': 10000,
        'greynoise': 166,           # 5K/mes ≈ 166/día
        'urlhaus': 10000,
        'threatfox': 10000,
        'malwarebazaar': 10000,
        'google_safebrowsing': 10000,
        'securitytrails': 2,         # 50/mes ≈ 2/día
        'hybrid_analysis': 200,
        # Nuevas
        'criminal_ip': 33,           # 1K/mes ≈ 33/día
        'pulsedive': 33,             # 1K/mes ≈ 33/día
        'urlscan': 1000,
        'shodan_internetdb': 'unlimited',
        'ip_api': 45,               # 45 req/min (gratis)
        'censys': 8,                 # 250/mes ≈ 8/día
        'ipinfo': 333,              # 10K/mes ≈ 333/día (lite)
        'ipgeolocation': 1000,      # 1K/día forever free (1 crédito/lookup)
        'tavily': 33,               # 1K créditos/mes ≈ 33/día (búsqueda web)
        'crtsh': 1000,              # sin key, sin límite oficial — tope conservador propio
        'nvd': 1000,                # sin key 5/30 s; con NVD_API_KEY 50/30 s — tope diario propio
        'cisa_kev': 1000,           # catálogo descargado y cacheado; sin límite oficial
        'epss': 1000,               # sin key, sin límite oficial documentado
        'exploitdb': 1000,          # dataset oficial cacheado; sin límite
    }

    # ==========================================================================
    # LLM Configuration
    # ==========================================================================
    LLM_MODELS = {
        'xai': {
            'model': 'grok-3-mini',          # grok-2-latest ya no existe
            'max_tokens': 4096,
            'temperature': 0.7,
            'base_url': 'https://api.x.ai/v1'
        },
        'openai': {
            'model': 'gpt-4o-mini',           # gpt-4-turbo-preview → gpt-4o-mini (más barato y rápido)
            'max_tokens': 4096,
            'temperature': 0.7
        },
        'deepseek': {
            'model': 'deepseek-flash',        # verificado en vivo 2026-11-13 (~2s); alterno: deepseek-v4-pro
            'max_tokens': 4096,
            'temperature': 0.7,
            'base_url': 'https://api.deepseek.com/v1'
        },
        'gemini': {
            'model': 'gemini-2.5-flash',      # REST API recomendada sobre SDK
            'max_tokens': 4096,
            'temperature': 0.7
        },
        'kimi': {
            'model': 'kimi-k3',               # verificado en vivo 2026-11-13 (~8s); alternos: kimi-k3.1-pro, kimi-k2.6
            'max_tokens': 4096,
            'temperature': 0.7,
            'fixed_temperature': 1,           # la API de Kimi rechaza cualquier temperature != 1
            'base_url': 'https://api.moonshot.ai/v1'  # .cn rechaza las keys internacionales
        }
    }

    # Orden de prioridad para LLMs
    LLM_PRIORITY = ['xai', 'openai', 'deepseek', 'gemini', 'kimi']

    # ==========================================================================
    # Session Investigation Settings
    # ==========================================================================
    SESSION_AUTO_CLOSE_HOURS = 24
    SESSION_MAX_MESSAGES = 200
    SESSION_COMPRESS_AFTER = 20

    # ==========================================================================
    # Logging
    # ==========================================================================
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOG_FILE = os.environ.get('LOG_FILE', 'logs/soc_agent.log')


class DevelopmentConfig(Config):
    DEBUG = True
    LOG_LEVEL = 'DEBUG'


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True

    # ==========================================================================
    # Rate limiting (Flask-Limiter) — Redis compartido entre workers gunicorn.
    # Sin esto, cada worker (--workers 3 en Dockerfile) cuenta con su propio
    # memory://, así que los límites reales son ~3x los configurados.
    # ==========================================================================
    RATELIMIT_STORAGE_URI = os.environ.get('RATELIMIT_STORAGE_URI') or os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    RATELIMIT_STORAGE_OPTIONS = {'socket_connect_timeout': 2}
    # Si Redis cae, degrada a memoria en vez de tirar 500s (verificado contra
    # flask_limiter.constants.ConfigVars en la versión instalada, 3.5.0).
    RATELIMIT_IN_MEMORY_FALLBACK_ENABLED = True

    # ==========================================================================
    # Cache (Flask-Caching) — mismo motivo: SimpleCache es por proceso/worker.
    # ==========================================================================
    CACHE_TYPE = 'RedisCache'
    CACHE_REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    CACHE_DEFAULT_TIMEOUT = 300

    @classmethod
    def init_app(cls, app=None):
        """Valida variables de entorno críticas antes de arrancar en producción."""
        secret = os.environ.get('SECRET_KEY')
        if not secret or len(secret) < 32:
            raise RuntimeError(
                "Production requires SECRET_KEY env var with at least 32 characters. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )

        chain_key = os.environ.get('AUDIT_CHAIN_KEY')
        if not chain_key or len(chain_key) < 32:
            raise RuntimeError(
                "Production requires AUDIT_CHAIN_KEY env var with at least 32 characters (clave HMAC de la cadena de auditoria; "
                "guardala FUERA de la BD y de sus backups). "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )

        database_url = os.environ.get('DATABASE_URL')
        if not database_url:
            raise RuntimeError(
                "Production requires DATABASE_URL env var. "
                "Example: postgresql://user:password@host:5432/dbname"
            )

        # ALLOWED_HOSTS valida la cabecera Host. El valor por defecto (127.0.0.1,localhost)
        # rechaza el dominio público detrás de un proxy: hay que declararlo explícitamente.
        if not os.environ.get('ALLOWED_HOSTS'):
            import logging
            logging.getLogger(__name__).warning(
                "ALLOWED_HOSTS no esta definido: solo se aceptaran peticiones con Host "
                "127.0.0.1/localhost. Detras de un proxy con dominio propio, definelo "
                "(p.ej. ALLOWED_HOSTS=soc.example.com) o toda peticion dara 400."
            )


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'TEST_DATABASE_URL',
        'postgresql://soc_admin:1234@localhost:5432/soc_agent_test?client_encoding=utf8'
    )
    # Desactivar rate limiting en tests (evita 429 por requests acumulados)
    RATELIMIT_ENABLED = False
    RATELIMIT_STORAGE_URI = 'memory://'


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}


def get_config():
    env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])