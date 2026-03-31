"""
Inicialización de la aplicación Flask SOC Agent
"""
from flask import Flask, g, request as flask_request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect

#from app.routes.dashboard_routes import bp as dashboard_bp
import json
import logging
import time
import uuid
from logging.handlers import RotatingFileHandler
import os


class JSONFormatter(logging.Formatter):
    """
    Formatter de logs en JSON estructurado.
    Facilita ingestión por SIEM/Elasticsearch.
    Incluye correlation ID por request cuando hay contexto Flask activo.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict = {
            'timestamp': self.formatTime(record, self.datefmt),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }

        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)

        # Agregar contexto de request si está disponible
        try:
            from flask import has_request_context
            if has_request_context():
                log_entry['request_id'] = getattr(g, 'request_id', None)
                log_entry['user_id'] = getattr(g, 'user_id', None)
                log_entry['method'] = flask_request.method
                log_entry['path'] = flask_request.path
        except RuntimeError:
            pass  # Fuera de contexto de aplicación

        return json.dumps(log_entry, ensure_ascii=False)

# Inicializar extensiones
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
limiter = Limiter(key_func=get_remote_address)
cache = Cache()
csrf = CSRFProtect()


def create_app(config_name='default'):
    """Factory para crear la aplicación Flask"""

    app = Flask(__name__)

    # Cargar configuración
    from app.config import config
    cfg = config[config_name]
    app.config.from_object(cfg)

    # Validar configuración (BUG-02 fix: init_app nunca se llamaba)
    if hasattr(cfg, 'init_app'):
        cfg.init_app(app)

    # Inicializar extensiones
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    limiter.init_app(app)
    cache.init_app(app)
    #app.register_blueprint(dashboard_bp)
    csrf.init_app(app)

    # CORS restringido a orígenes permitidos
    CORS(app, resources={
        r"/api/*": {
            "origins": app.config.get('CORS_ORIGINS', ['http://127.0.0.1:5000']),
            "methods": ["GET", "POST", "PUT", "DELETE"],
            "allow_headers": ["Content-Type", "Authorization", "X-CSRFToken"],
            "supports_credentials": True
        }
    })

    # IMPORTANTE: Importar modelos DESPUÉS de inicializar db
    with app.app_context():
        from app.models import ioc  # noqa: F401
        from app.models import audit  # noqa: F401

    # Configurar login
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Por favor inicia sesión para acceder.'

    # Configurar logging
    setup_logging(app)

    # Registrar blueprints
    register_blueprints(app)

    # Registrar CLI commands
    from app.cli import mitre_cli
    app.cli.add_command(mitre_cli)

    # Registrar manejadores de errores
    register_error_handlers(app)

    # Correlation ID por request (T3B-05)
    register_request_context(app)

    # Métricas de performance (T5C-01)
    register_metrics_collector(app)

    # Security headers
    register_security_headers(app)

    # Security middleware (input validation, anti-injection)
    from app.middleware.security import init_security
    init_security(app)

    # Inicializar Sentry (si está configurado)
    sentry_dsn = app.config.get('SENTRY_DSN')
    if sentry_dsn and sentry_dsn.strip() and sentry_dsn != 'your_sentry_dsn':
        try:
            import sentry_sdk
            from sentry_sdk.integrations.flask import FlaskIntegration
            sentry_sdk.init(
                dsn=sentry_dsn,
                integrations=[FlaskIntegration()],
                traces_sample_rate=0.05,
                send_default_pii=False,
            )
            app.logger.info("Sentry initialized")
        except Exception as e:
            app.logger.warning(f"Sentry initialization failed: {e}")


    return app


def register_blueprints(app):
    """Registra todos los blueprints de la aplicación"""
    from app.routes.main import main_bp
    from app.routes.auth import auth_bp
    from app.routes.api_v2_routes import bp as api_v2_bp
    from app.routes.report_routes import bp as reports_bp
    from app.routes.dashboard_routes import bp as dashboard_bp
    from app.routes.incident_routes import bp as incidents_api_bp
    from app.routes.mitre_stix_routes import bp as mitre_stix_bp
    from app.docs.openapi import docs_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(api_v2_bp, url_prefix='/api/v2')
    app.register_blueprint(reports_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(incidents_api_bp)
    app.register_blueprint(mitre_stix_bp)
    app.register_blueprint(docs_bp)

    # Eximir API blueprints de CSRF
    csrf.exempt(api_v2_bp)
    csrf.exempt(reports_bp)
    csrf.exempt(incidents_api_bp)
    csrf.exempt(mitre_stix_bp)
    csrf.exempt(docs_bp)


def register_metrics_collector(app: Flask) -> None:
    """Registra métricas de performance por endpoint en after_request."""

    @app.after_request
    def collect_request_metrics(response):
        try:
            start = getattr(g, '_request_start', None)
            if start is not None:
                latency_ms = (time.monotonic() - start) * 1000
                from app.utils.metrics import record_request_time
                record_request_time(
                    endpoint=flask_request.path,
                    latency_ms=latency_ms,
                    success=response.status_code < 500,
                )
        except Exception:
            pass
        return response


def register_security_headers(app):
    """Agrega headers de seguridad a todas las respuestas"""

    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'

        if not app.debug:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        # CSP - ajustado para Tailwind CDN, Chart.js, Font Awesome, Leaflet
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.tailwindcss.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.tailwindcss.com; "
            "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
            "img-src 'self' data: https://*.tile.openstreetmap.org; "
            "connect-src 'self'"
        )
        return response


def register_error_handlers(app):
    """Registra manejadores de errores personalizados"""

    @app.errorhandler(400)
    def bad_request(error):
        return {'error': 'Bad Request', 'message': str(error)}, 400

    @app.errorhandler(404)
    def not_found(error):
        return {'error': 'Not Found', 'message': 'Recurso no encontrado'}, 404

    @app.errorhandler(429)
    def ratelimit_handler(error):
        return {'error': 'Rate Limit Exceeded', 'message': 'Demasiadas solicitudes'}, 429

    @app.errorhandler(413)
    def request_entity_too_large(error):
        return {'error': 'Request Too Large', 'message': 'El cuerpo de la solicitud supera el límite de 16 MB'}, 413

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        app.logger.error(f'Server Error: {error}')
        return {'error': 'Internal Server Error', 'message': 'Error interno del servidor'}, 500


def register_request_context(app: Flask) -> None:
    """Inyecta correlation ID y user_id en cada request (T3B-05)."""

    @app.before_request
    def set_request_context() -> None:
        g.request_id = str(uuid.uuid4())
        g._request_start = time.monotonic()
        try:
            from flask_login import current_user
            if current_user.is_authenticated:
                g.user_id = current_user.id
            else:
                g.user_id = None
        except Exception:
            g.user_id = None


def setup_logging(app: Flask) -> None:
    """
    Configura el sistema de logging con JSONFormatter.
    En producción: RotatingFileHandler JSON.
    En desarrollo: StreamHandler JSON (stdout).
    """
    log_level = getattr(logging, app.config.get('LOG_LEVEL', 'INFO'))
    json_formatter = JSONFormatter()

    if not app.debug and not app.testing:
        # Crear directorio de logs si no existe
        if not os.path.exists('logs'):
            os.mkdir('logs')

        # Handler para archivo con formato JSON
        file_handler = RotatingFileHandler(
            app.config['LOG_FILE'],
            maxBytes=10240000,  # 10MB
            backupCount=10
        )
        file_handler.setFormatter(json_formatter)
        file_handler.setLevel(log_level)
        app.logger.addHandler(file_handler)

    else:
        # En desarrollo: stream handler con JSON para consistencia
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(json_formatter)
        stream_handler.setLevel(log_level)
        # Solo agregar si no hay handlers ya (evitar duplicados en testing)
        if not app.logger.handlers:
            app.logger.addHandler(stream_handler)

    app.logger.setLevel(log_level)
    if not app.testing:
        app.logger.info('SOC Agent startup')


@login_manager.user_loader
def load_user(user_id):
    """Carga el usuario desde la base de datos"""
    # Import aquí para evitar circular import
    from app.models.ioc import User
    return db.session.get(User, int(user_id))