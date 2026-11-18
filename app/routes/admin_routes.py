"""
Administración de cuentas bloqueadas por intentos de login fallidos (desbloqueo manual).

  GET  /api/v2/admin/locked-accounts   -> cuentas bloqueadas ahora (solo admin)
  POST /api/v2/admin/accounts/unlock   -> desbloquea un nombre de usuario (solo admin)
  GET  /admin/accounts                 -> página con ambas cosas (solo admin)

Si el propio administrador queda bloqueado y no puede entrar a la web: `flask accounts unlock <usuario>`
(app/cli/account_commands.py).
"""
from flask import Blueprint, jsonify, render_template, request
from flask_login import login_required

from app import limiter
from app.utils.auth import require_role
from app.utils.login_throttle import MAX_USERNAME_LEN, locked_accounts, unlock_account
from app.utils.responses import safe_error_response

bp = Blueprint('admin_api', __name__, url_prefix='/api/v2/admin')
pages_bp = Blueprint('admin_pages', __name__)


@bp.route('/locked-accounts', methods=['GET'])
@login_required
@require_role('admin')
def list_locked_accounts():
    """Cuentas bloqueadas AHORA, con la misma regla que aplica el login."""
    try:
        cuentas = locked_accounts()
        return jsonify({'success': True, 'count': len(cuentas), 'accounts': cuentas}), 200
    except Exception as e:
        return safe_error_response(e, "Locked accounts error")


@bp.route('/accounts/unlock', methods=['POST'])
@login_required
@require_role('admin')
@limiter.limit("30 per minute")
def unlock():
    """
    Desbloquea un nombre de usuario y reinicia su contador de fallos.

    Body JSON: {"username": "ana"}   (no distingue mayúsculas ni espacios, igual que el bloqueo)
    Respuesta: {"success": true, "username": "ana", "was_locked": true|false}
    Es idempotente y siempre deja un evento 'account_unlocked' en la auditoría (con el admin que lo hizo).
    """
    data = request.get_json(silent=True)
    username = data.get('username') if isinstance(data, dict) else None
    if not isinstance(username, str) or not username.strip():
        return jsonify({'error': 'username requerido'}), 400
    if len(username.strip()) > MAX_USERNAME_LEN:
        return jsonify({'error': f'username demasiado largo (máx. {MAX_USERNAME_LEN})'}), 400
    try:
        result = unlock_account(username)           # el admin se toma de la sesión
        return jsonify({'success': True, **result}), 200
    except Exception as e:
        return safe_error_response(e, "Unlock account error")


@pages_bp.route('/admin/accounts')
@login_required
@require_role('admin')
def accounts_page():
    return render_template('admin_accounts.html')
