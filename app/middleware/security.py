"""
Security Middleware - Validacion y Sanitizacion de Entrada
SOC Agent - Hardening de Seguridad

Protecciones:
- SQL Injection detection y bloqueo
- XSS (Cross-Site Scripting) sanitizacion
- Command Injection detection
- Path Traversal detection
- Session hardening
- Input length limits
- Content-Type validation
- Logging de intentos maliciosos
"""
import re
import logging
import html
from functools import wraps
from datetime import datetime
from flask import request, abort, jsonify, session, current_app

logger = logging.getLogger('security')


# =============================================================================
# PATRONES DE ATAQUE
# =============================================================================

# SQL Injection patterns
SQL_INJECTION_PATTERNS = [
    # Union-based
    r"(?i)\bunion\b.*\bselect\b",
    r"(?i)\bunion\b.*\ball\b.*\bselect\b",
    # Boolean-based
    r"(?i)\bor\b\s+\d+\s*=\s*\d+",
    r"(?i)\band\b\s+\d+\s*=\s*\d+",
    r"(?i)\bor\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?",
    # Error-based
    r"(?i)\bextractvalue\b",
    r"(?i)\bupdatexml\b",
    # Stacked queries
    r";\s*(?:drop|alter|create|insert|update|delete|truncate)\b",
    # Common payloads
    r"(?i)(?:--|#|/\*)\s*$",    # Comment terminators
    r"(?i)\bexec\b.*\bxp_",     # SQL Server xp_
    r"(?i)\binto\b\s+\boutfile\b",
    r"(?i)\bload_file\b\s*\(",
    r"(?i)\binformation_schema\b",
    r"(?i)\bsys\.\w+\b",
    r"(?i)'\s*;\s*\b(?:drop|delete|update|insert)\b",
    r"(?i)\bwaitfor\b\s+\bdelay\b",
    r"(?i)\bbenchmark\b\s*\(",
    r"(?i)\bsleep\b\s*\(\s*\d+\s*\)",
]

# XSS patterns
XSS_PATTERNS = [
    r"<script[^>]*>",
    r"</script>",
    r"javascript\s*:",
    r"on\w+\s*=\s*['\"]",      # Event handlers: onclick=, onerror=, etc
    r"<iframe[^>]*>",
    r"<object[^>]*>",
    r"<embed[^>]*>",
    r"<svg[^>]*on\w+",
    r"<img[^>]*onerror",
    r"expression\s*\(",         # CSS expression
    r"url\s*\(\s*javascript",
    r"<\s*meta[^>]*http-equiv",
    r"document\.\w+",
    r"window\.\w+",
    r"eval\s*\(",
    r"alert\s*\(",
    r"String\.fromCharCode",
]

# Command Injection patterns
CMD_INJECTION_PATTERNS = [
    r";\s*(?:ls|cat|rm|wget|curl|bash|sh|nc|ncat|python|perl|ruby)\b",
    r"\|\s*(?:ls|cat|rm|wget|curl|bash|sh|nc|ncat)\b",
    r"`[^`]*`",                 # Backtick execution
    r"\$\([^)]*\)",             # $() execution
    r"&&\s*\w+",
    r"\|\|\s*\w+",
]

# Path Traversal patterns
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e[/\\]",
    r"%252e%252e",
    r"\.\.%2f",
    r"\.\.%5c",
    r"/etc/(?:passwd|shadow|hosts)",
    r"[/\\]windows[/\\]system32",
    r"[/\\]proc[/\\]self",
]

# Compile patterns for performance
_sqli_compiled = [re.compile(p) for p in SQL_INJECTION_PATTERNS]
_xss_compiled = [re.compile(p, re.IGNORECASE) for p in XSS_PATTERNS]
_cmd_compiled = [re.compile(p) for p in CMD_INJECTION_PATTERNS]
_path_compiled = [re.compile(p, re.IGNORECASE) for p in PATH_TRAVERSAL_PATTERNS]


# =============================================================================
# DETECTION FUNCTIONS
# =============================================================================

def detect_sqli(value: str) -> bool:
    """Detecta intentos de SQL injection"""
    if not value:
        return False
    for pattern in _sqli_compiled:
        if pattern.search(value):
            return True
    return False


def detect_xss(value: str) -> bool:
    """Detecta intentos de XSS"""
    if not value:
        return False
    for pattern in _xss_compiled:
        if pattern.search(value):
            return True
    return False


def detect_cmd_injection(value: str) -> bool:
    """Detecta intentos de command injection"""
    if not value:
        return False
    for pattern in _cmd_compiled:
        if pattern.search(value):
            return True
    return False


def detect_path_traversal(value: str) -> bool:
    """Detecta intentos de path traversal"""
    if not value:
        return False
    for pattern in _path_compiled:
        if pattern.search(value):
            return True
    return False


def detect_all_threats(value: str) -> list:
    """Ejecuta todas las detecciones y retorna lista de amenazas"""
    threats = []
    if detect_sqli(value):
        threats.append('SQL_INJECTION')
    if detect_xss(value):
        threats.append('XSS')
    if detect_cmd_injection(value):
        threats.append('CMD_INJECTION')
    if detect_path_traversal(value):
        threats.append('PATH_TRAVERSAL')
    return threats


# =============================================================================
# SANITIZATION FUNCTIONS
# =============================================================================

def sanitize_string(value: str, max_length: int = 5000) -> str:
    """
    Sanitiza un string eliminando contenido peligroso.
    Preserva IOCs validos (IPs, hashes, dominios).
    """
    if not isinstance(value, str):
        return str(value)[:max_length]

    # Truncar a longitud maxima
    value = value[:max_length]

    # HTML escape (previene XSS en output)
    value = html.escape(value, quote=True)

    # Eliminar null bytes
    value = value.replace('\x00', '')

    # Eliminar caracteres de control (excepto newline, tab)
    value = re.sub(r'[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)

    return value.strip()


def sanitize_ioc_input(ioc_value: str) -> str:
    """
    Sanitiza input de IOC preservando caracteres validos.
    IOCs pueden contener: IPs, dominios, hashes, URLs
    """
    if not ioc_value:
        return ''

    # Trim y limitar longitud
    ioc_value = ioc_value.strip()[:2048]

    # Solo permitir caracteres validos para IOCs
    # a-zA-Z0-9, puntos, guiones, barras, dos puntos, corchetes (IPv6), @, %, =
    ioc_value = re.sub(r'[^\w\.\-/:@%=\[\]?&#+]', '', ioc_value)

    return ioc_value


def sanitize_dict(data: dict, max_depth: int = 5, _depth: int = 0) -> dict:
    """Sanitiza recursivamente un diccionario"""
    if _depth >= max_depth:
        return {}

    sanitized = {}
    for key, value in data.items():
        # Sanitizar key
        clean_key = sanitize_string(str(key), max_length=200)

        if isinstance(value, str):
            sanitized[clean_key] = sanitize_string(value)
        elif isinstance(value, dict):
            sanitized[clean_key] = sanitize_dict(value, max_depth, _depth + 1)
        elif isinstance(value, list):
            sanitized[clean_key] = [
                sanitize_string(v) if isinstance(v, str)
                else sanitize_dict(v, max_depth, _depth + 1) if isinstance(v, dict)
                else v
                for v in value[:100]  # Limitar arrays a 100 items
            ]
        else:
            sanitized[clean_key] = value

    return sanitized


# =============================================================================
# FLASK MIDDLEWARE
# =============================================================================

def init_security(app):
    """
    Inicializa middleware de seguridad en la app Flask.
    Llamar desde __init__.py: init_security(app)
    """

    # Configuracion de sesion segura
    app.config.setdefault('SESSION_COOKIE_HTTPONLY', True)
    app.config.setdefault('SESSION_COOKIE_SAMESITE', 'Lax')
    app.config.setdefault('PERMANENT_SESSION_LIFETIME', 3600)  # 1 hora
    app.config.setdefault('SESSION_COOKIE_NAME', 'soc_session')

    # Si HTTPS
    if app.config.get('PREFERRED_URL_SCHEME') == 'https':
        app.config['SESSION_COOKIE_SECURE'] = True

    @app.before_request
    def security_check():
        """Middleware que valida todas las requests"""

        # Skip para static files
        if request.path.startswith('/static'):
            return None

        # Skip para health check
        if request.path == '/api/v2/health':
            return None

        # ============================================
        # 1. Validar tamanio del request
        # ============================================
        content_length = request.content_length
        max_size = 10 * 1024 * 1024  # 10MB
        if content_length and content_length > max_size:
            _log_security_event('OVERSIZED_REQUEST', f'Size: {content_length}')
            abort(413)

        # ============================================
        # 2. Validar URL path
        # ============================================
        if detect_path_traversal(request.path):
            _log_security_event('PATH_TRAVERSAL', f'Path: {request.path}')
            abort(400)

        # ============================================
        # 3. Validar query parameters
        # ============================================
        for key, value in request.args.items():
            threats = detect_all_threats(value)
            if threats:
                _log_security_event(
                    'MALICIOUS_QUERY_PARAM',
                    f'Param: {key}={value[:100]} | Threats: {threats}'
                )
                abort(400)

        # ============================================
        # 4. Validar form data (POST)
        # ============================================
        if request.method in ('POST', 'PUT', 'PATCH') and request.form:
            for key, value in request.form.items():
                if key in ('csrf_token', 'password', 'current_password',
                           'new_password', 'new_password2'):
                    continue  # No validar tokens ni passwords
                threats = detect_all_threats(value)
                if threats:
                    _log_security_event(
                        'MALICIOUS_FORM_DATA',
                        f'Field: {key}={value[:100]} | Threats: {threats}'
                    )
                    abort(400)

        # ============================================
        # 5. Validar JSON body
        # ============================================
        if request.is_json:
            try:
                data = request.get_json(silent=True)
                if data and isinstance(data, dict):
                    _check_json_recursive(data)
            except SecurityViolation as e:
                _log_security_event('MALICIOUS_JSON', str(e))
                abort(400)

        # ============================================
        # 6. Session fixation protection
        # ============================================
        if 'initialized' not in session:
            session['initialized'] = True
            session['created_at'] = datetime.utcnow().isoformat()

        return None

    @app.after_request
    def add_security_headers(response):
        """Agrega headers de seguridad adicionales"""
        # Prevenir caching de contenido sensible
        if request.path.startswith('/api/') or request.path.startswith('/auth/'):
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'

        return response


class SecurityViolation(Exception):
    """Excepcion para violaciones de seguridad detectadas"""
    pass


def _check_json_recursive(data, path='', depth=0):
    """Valida recursivamente JSON body buscando payloads maliciosos"""
    if depth > 10:
        raise SecurityViolation(f'JSON depth exceeded at {path}')

    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f'{path}.{key}' if path else key

            # No validar campos que pueden contener contenido libre
            if key in ('message', 'content', 'description', 'conclusion',
                       'context', 'notes', 'llm_analysis', 'recommendation',
                       'password', 'current_password', 'new_password'):
                continue

            if isinstance(value, str):
                # Validar IOC inputs (pueden parecer maliciosos pero son validos)
                if key in ('ioc', 'ioc_value', 'value', 'query'):
                    # Solo verificar SQLi y cmd injection, no XSS (IOCs tienen chars especiales)
                    if detect_sqli(value) or detect_cmd_injection(value):
                        raise SecurityViolation(
                            f'Potential injection at {current_path}: {value[:50]}'
                        )
                else:
                    threats = detect_all_threats(value)
                    if threats:
                        raise SecurityViolation(
                            f'Threats {threats} at {current_path}: {value[:50]}'
                        )
            elif isinstance(value, (dict, list)):
                _check_json_recursive(value, current_path, depth + 1)

    elif isinstance(data, list):
        for i, item in enumerate(data[:100]):  # Limitar a 100 items
            _check_json_recursive(item, f'{path}[{i}]', depth + 1)


def _log_security_event(event_type: str, details: str):
    """Log de eventos de seguridad"""
    from flask_login import current_user

    user_info = 'anonymous'
    if hasattr(current_user, 'username') and current_user.is_authenticated:
        user_info = current_user.username

    ip = request.remote_addr
    ua = request.user_agent.string[:200] if request.user_agent else 'unknown'

    logger.warning(
        f"[SECURITY] {event_type} | IP: {ip} | User: {user_info} | "
        f"Path: {request.path} | Method: {request.method} | "
        f"UA: {ua} | Details: {details}"
    )


# =============================================================================
# DECORATORS PARA RUTAS
# =============================================================================

def validate_ioc_input(f):
    """Decorator que valida y sanitiza IOC input en endpoints de analisis"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.is_json:
            data = request.get_json(silent=True)
            if data and 'ioc' in data:
                ioc = data['ioc']
                # Verificar longitud
                if len(ioc) > 2048:
                    return jsonify({'error': 'IOC demasiado largo (max 2048 chars)'}), 400
                # Sanitizar
                data['ioc'] = sanitize_ioc_input(ioc)
                if not data['ioc']:
                    return jsonify({'error': 'IOC invalido despues de sanitizacion'}), 400
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Decorator que requiere rol admin"""
    @wraps(f)
    def decorated(*args, **kwargs):
        from flask_login import current_user
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated
