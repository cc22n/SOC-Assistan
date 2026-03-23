"""
Inicialización de la aplicación Flask SOC Agent
"""
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect

#from app.routes.dashboard_routes import bp as dashboard_bp
import logging
from logging.handlers import RotatingFileHandler
import os

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
        from app.models import ioc

    # Configurar login
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Por favor inicia sesión para acceder.'

    # Configurar logging
    setup_logging(app)

    # Registrar blueprints
    register_blueprints(app)

    # Registrar manejadores de errores
    register_error_handlers(app)

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
    from app.docs.openapi import docs_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(api_v2_bp, url_prefix='/api/v2')
    app.register_blueprint(reports_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(incidents_api_bp)
    app.register_blueprint(docs_bp)

    # Eximir API blueprints de CSRF (usan autenticacion por sesion/token, no formularios)
    csrf.exempt(api_v2_bp)
    csrf.exempt(reports_bp)
    csrf.exempt(incidents_api_bp)
    csrf.exempt(docs_bp)


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

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        app.logger.error(f'Server Error: {error}')
        return {'error': 'Internal Server Error', 'message': 'Error interno del servidor'}, 500


def setup_logging(app):
    """Configura el sistema de logging"""

    if not app.debug and not app.testing:
        # Crear directorio de logs si no existe
        if not os.path.exists('logs'):
            os.mkdir('logs')

        # Handler para archivo
        file_handler = RotatingFileHandler(
            app.config['LOG_FILE'],
            maxBytes=10240000,  # 10MB
            backupCount=10
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(getattr(logging, app.config['LOG_LEVEL']))

        app.logger.addHandler(file_handler)
        app.logger.setLevel(getattr(logging, app.config['LOG_LEVEL']))
        app.logger.info('SOC Agent startup')


@login_manager.user_loader
def load_user(user_id):
    """Carga el usuario desde la base de datos"""
    # Import aquí para evitar circular import
    from app.models.ioc import User
    return db.session.get(User, int(user_id))