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

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL',
                                             'postgresql://soc_admin:soc_password@localhost:5432/soc_agent')

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }

    # Redis
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')

    # Session
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)

    # ==========================================================================
    # Security - Cookies
    # ==========================================================================
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_DURATION = timedelta(days=7)

    # ==========================================================================
    # Security - CORS Allowed Origins
    # ==========================================================================
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', 'http://127.0.0.1:5000,http://localhost:5000').split(',')

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

        # === LLM Providers ===
        'xai': os.environ.get('XAI_API_KEY'),
        'openai': os.environ.get('OPENAI_API_KEY'),
        'groq': os.environ.get('GROQ_API_KEY'),
        'gemini': os.environ.get('GEMINI_API_KEY'),
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
        'groq': {
            'model': 'llama-3.3-70b-versatile',  # llama-3.1-70b decomisado → llama-3.3-70b
            'max_tokens': 4096,
            'temperature': 0.7,
            'base_url': 'https://api.groq.com/openai/v1'
        },
        'gemini': {
            'model': 'gemini-2.5-flash',      # REST API recomendada sobre SDK
            'max_tokens': 4096,
            'temperature': 0.7
        }
    }

    # Orden de prioridad para LLMs
    LLM_PRIORITY = ['xai', 'openai', 'groq', 'gemini']

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

    @classmethod
    def init_app(cls):
        secret = os.environ.get('SECRET_KEY')
        if not secret or len(secret) < 32:
            raise RuntimeError(
                "Production requires SECRET_KEY env var with at least 32 characters. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'TEST_DATABASE_URL',
        'postgresql://soc_admin:1234@localhost:5432/soc_agent_test?client_encoding=utf8'
    )


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}


def get_config():
    env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])