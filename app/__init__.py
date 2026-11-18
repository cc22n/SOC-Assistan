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

import json
import logging
import time
import uuid
from logging.handlers import RotatingFileHandler
import os
import sys


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
        from app.models import mitre  # noqa: F401

    # Configurar login
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Por favor inicia sesión para acceder.'

    # Configurar logging
    setup_logging(app)

    # Validar la cabecera Host (ALLOWED_HOSTS). Va ANTES que el resto de before_request
    # (Flask los ejecuta en orden de registro): un Host no permitido se rechaza sin tocar BD.
    register_host_validation(app)

    # Registrar blueprints
    register_blueprints(app)

    # Registrar CLI commands
    from app.cli import mitre_cli, accounts_cli
    app.cli.add_command(mitre_cli)
    app.cli.add_command(accounts_cli)

    # Filtro Jinja para mostrar fechas en hora local (México) en templates
    # server-side rendered — los timestamps se guardan en UTC naive
    register_template_filters(app)

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
    from app.routes.deep_analysis_routes import bp as deep_bp
    from app.routes.admin_routes import bp as admin_api_bp, pages_bp as admin_pages_bp
    from app.docs.openapi import docs_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(api_v2_bp, url_prefix='/api/v2')
    app.register_blueprint(reports_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(incidents_api_bp)
    app.register_blueprint(mitre_stix_bp)
    app.register_blueprint(deep_bp)
    app.register_blueprint(admin_api_bp)
    app.register_blueprint(admin_pages_bp)
    app.register_blueprint(docs_bp)

    # Eximir únicamente endpoints de documentación pública de CSRF
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
                    # endpoint (p.ej. 'incidents_api.get_incident'), NO el path: con path cada
                    # /incidents/<id> y cada URL 404 aleatoria creaba una serie nueva (fuga de RAM)
                    endpoint=flask_request.endpoint or 'unmatched',
                    latency_ms=latency_ms,
                    success=response.status_code < 500,
                )
        except Exception as _e:
            app.logger.debug(f"Metrics collector error: {_e}")
        return response


def register_host_validation(app: Flask) -> None:
    """
    Rechaza con 400 las peticiones cuyo Host no esté en ALLOWED_HOSTS (Host Header Poisoning).
    Detrás de un proxy, wsgi.py aplica ProxyFix(x_host=1) y request.host refleja
    X-Forwarded-Host, de modo que se valida el host público real.
    """
    from flask import Response
    from app.utils.hosts import host_allowed

    @app.before_request
    def _validate_host_header():
        allowed = app.config.get('ALLOWED_HOSTS')
        if not allowed:
            return None
        if host_allowed(flask_request.host, allowed):
            return None
        app.logger.warning(
            "Host rechazado por ALLOWED_HOSTS: %r (ip=%s, path=%s)",
            flask_request.host[:100], flask_request.remote_addr, flask_request.path[:100])
        return Response('Invalid Host header', status=400, mimetype='text/plain')


def build_csp(nonce: str, upgrade_insecure: bool = False) -> str:
    """
    Content-Security-Policy estricta para scripts (ALTO-11).

    script-src
      'nonce-X' + 'strict-dynamic': solo ejecutan los <script> que el servidor marcó con el
      nonce de ESTA respuesta (y lo que ellos carguen). Un <script> inyectado por XSS no lo
      lleva y no corre. Los hosts de CDN quedan solo como respaldo para navegadores sin
      soporte de strict-dynamic (CSP2); los modernos los ignoran.
    script-src-attr 'none': prohíbe handlers inline (onclick=...); las plantillas usan
      data-action + static/ui-actions.js.
    style-src / style-src-elem: 'self' + nonce (sin 'unsafe-inline'). Cada <style> lleva el nonce; Tailwind
      se COMPILA (app/static/css/tailwind.css, scripts/build_css.sh) en vez de generarse en el navegador
      con el CDN, que era lo que obligaba a 'unsafe-inline' y a permitir un script de terceros sin versión.
    style-src-attr 'unsafe-inline': RESIDUAL y deliberado. Los atributos style="..." (y los que escribe el
      JS de las plantillas) no se pueden proteger con nonce; el riesgo es mucho menor que el de un <style>
      o un <script> inyectado (no ejecuta código; solo permite alterar la apariencia).
    Los recursos de CDN (Chart.js, Leaflet, Font Awesome) llevan SRI (integrity + crossorigin).
    """
    directives = [
        "default-src 'self'",
        f"script-src 'nonce-{nonce}' 'strict-dynamic' https://cdn.jsdelivr.net "
        "https://cdnjs.cloudflare.com",
        "script-src-attr 'none'",
        f"style-src 'self' 'nonce-{nonce}' https://cdnjs.cloudflare.com https://fonts.googleapis.com",
        f"style-src-elem 'self' 'nonce-{nonce}' https://cdnjs.cloudflare.com https://fonts.googleapis.com",
        "style-src-attr 'unsafe-inline'",
        "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com",
        "img-src 'self' data: https://*.tile.openstreetmap.org",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ]
    if upgrade_insecure:
        directives.append("upgrade-insecure-requests")
    return "; ".join(directives)


def register_security_headers(app):
    """Agrega headers de seguridad a todas las respuestas"""
    import secrets

    @app.before_request
    def _generate_csp_nonce():
        g.csp_nonce = secrets.token_urlsafe(16)   # 128 bits, distinto en CADA petición

    @app.context_processor
    def _inject_csp_nonce():
        # En plantillas: <script nonce="{{ csp_nonce() }}">. Fuera de una petición devuelve ''.
        return {'csp_nonce': lambda: getattr(g, 'csp_nonce', '')}

    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'

        if not app.debug:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        # CSP con nonce por petición (ver build_csp). Se usa el MISMO nonce que las plantillas.
        nonce = getattr(g, 'csp_nonce', None) or secrets.token_urlsafe(16)
        response.headers['Content-Security-Policy'] = build_csp(
            nonce, upgrade_insecure=not (app.debug or app.testing))
        return response


def register_template_filters(app: Flask) -> None:
    """
    Filtro `local_dt` para templates: convierte un datetime UTC naive
    (formato de almacenamiento de app.utils.time_utils.utcnow()) a la zona
    horaria configurada en DISPLAY_TIMEZONE y lo formatea con strftime.
    Sin esto, {{ x.created_at.strftime(...) }} renderiza hora UTC cruda.
    """
    from datetime import timezone
    from zoneinfo import ZoneInfo

    @app.template_filter('local_dt')
    def local_dt(value, fmt='%d/%m/%Y %H:%M'):
        if value is None:
            return '-'
        tz = ZoneInfo(app.config.get('DISPLAY_TIMEZONE', 'America/Mexico_City'))
        aware = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
        return aware.astimezone(tz).strftime(fmt)


def register_error_handlers(app):
    """Registra manejadores de errores personalizados (híbrido HTML y JSON)"""
    from flask import render_template

    def wants_json():
        if flask_request.path.startswith('/api/') or flask_request.is_json:
            return True
        best = flask_request.accept_mimetypes.best_match(['application/json', 'text/html'])
        return best == 'application/json' and flask_request.accept_mimetypes[best] > flask_request.accept_mimetypes['text/html']

    @app.errorhandler(400)
    def bad_request(error):
        msg = str(error) if app.debug else 'Bad request'
        if wants_json():
            return {'success': False, 'error': 'Bad Request', 'message': msg}, 400
        return render_template('errors/400.html', message=msg), 400

    @app.errorhandler(403)
    def forbidden(error):
        msg = str(error) if app.debug else 'Acceso denegado'
        if wants_json():
            return {'success': False, 'error': 'Forbidden', 'message': msg}, 403
        return render_template('errors/403.html', message=msg), 403

    @app.errorhandler(404)
    def not_found(error):
        if wants_json():
            return {'success': False, 'error': 'Not Found', 'message': 'Recurso no encontrado'}, 404
        return render_template('errors/404.html'), 404

    @app.errorhandler(429)
    def ratelimit_handler(error):
        if wants_json():
            return {'success': False, 'error': 'Rate Limit Exceeded', 'message': 'Demasiadas solicitudes'}, 429
        return render_template('errors/429.html'), 429

    @app.errorhandler(413)
    def request_entity_too_large(error):
        if wants_json():
            return {'success': False, 'error': 'Request Too Large', 'message': 'El cuerpo de la solicitud supera el límite de 16 MB'}, 413
        return render_template('errors/413.html'), 413

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        app.logger.error(f'Server Error: {error}')
        if wants_json():
            return {'success': False, 'error': 'Internal Server Error', 'message': 'Error interno del servidor'}, 500
        return render_template('errors/500.html'), 500


def register_request_context(app: Flask) -> None:
    """Inyecta correlation ID y user_id en cada request (T3B-05) y cabecera en respuesta."""

    @app.before_request
    def set_request_context() -> None:
        incoming_id = flask_request.headers.get('X-Request-ID')
        g.request_id = incoming_id if incoming_id else str(uuid.uuid4())
        g._request_start = time.monotonic()
        try:
            from flask_login import current_user
            if current_user.is_authenticated:
                g.user_id = current_user.id
            else:
                g.user_id = None
        except Exception:
            g.user_id = None

    @app.after_request
    def inject_request_id_header(response):
        if hasattr(g, 'request_id') and g.request_id:
            response.headers['X-Request-ID'] = g.request_id
        return response


def setup_logging(app: Flask) -> None:
    """
    Configura el sistema de logging con JSONFormatter.
    En producción: Dual logging (RotatingFileHandler JSON + StreamHandler a stdout para Docker logs).
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

        # StreamHandler a stdout para logs de Docker
        stdout_handler = logging.StreamHandler(sys.stdout)
        stdout_handler.setFormatter(json_formatter)
        stdout_handler.setLevel(log_level)
        app.logger.addHandler(stdout_handler)

    else:
        # En desarrollo: stream handler con JSON para consistencia
        stream_handler = logging.StreamHandler(sys.stdout)
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