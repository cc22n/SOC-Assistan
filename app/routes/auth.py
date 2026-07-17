"""
Rutas de autenticación
"""
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from urllib.parse import urlparse  # Cambiado de werkzeug.urls
from app.models.ioc import User
from app import db, limiter

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"])
@limiter.limit("20 per hour", methods=["POST"])
def login():
    """Login de usuario"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False)

        if not username or not password:
            flash('Por favor completa todos los campos', 'error')
            return render_template('auth/login.html')

        user = User.query.filter_by(username=username).first()

        if user is None or not user.check_password(password):
            from app.models.audit import AuditEvent
            AuditEvent.log('login_failed', success=False,
                           details={'username': username, 'reason': 'invalid_credentials'},
                           _commit=True)
            flash('Usuario o contraseña incorrectos', 'error')
            return render_template('auth/login.html')

        if not user.is_active:
            flash('Usuario desactivado. Contacta al administrador', 'error')
            return render_template('auth/login.html')

        login_user(user, remember=remember)

        # Actualizar last_login
        from app.utils.time_utils import utcnow
        user.last_login = utcnow()
        db.session.commit()

        from app.models.audit import AuditEvent
        AuditEvent.log('login', resource_type='user', resource_id=user.id,
                       details={'username': user.username}, user_id=user.id, username=user.username,
                       _commit=True)

        # Redirect a la página solicitada o dashboard (VULN-03 fix)
        next_page = request.args.get('next')
        if next_page:
            parsed = urlparse(next_page)
            # Rechazar URLs externas Y javascript: URIs
            if parsed.netloc != '' or parsed.scheme not in ('', 'http', 'https'):
                next_page = None
        if not next_page:
            next_page = url_for('main.dashboard')

        flash(f'Bienvenido {user.username}!', 'success')
        return redirect(next_page)

    return render_template('auth/login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    """Logout de usuario"""
    from app.models.audit import AuditEvent
    AuditEvent.log('logout', resource_type='user', resource_id=current_user.id, _commit=True)
    logout_user()
    flash('Sesión cerrada correctamente', 'info')
    return redirect(url_for('main.index'))


@auth_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per minute", methods=["POST"])
def register():
    """Crear usuario — solo admin, o bootstrap inicial cuando no hay usuarios."""
    if request.method == 'POST':
        # Advisory lock previene race condition TOCTOU: dos POST concurrentes
        # contra una tabla users vacia podrian leer count()==0 ambos y crear
        # dos cuentas admin sin autenticacion. Se limita a POST (el GET solo
        # renderiza el form y no necesita serializarse).
        from sqlalchemy import text
        db.session.execute(text("SELECT pg_advisory_xact_lock(735202)"))
    is_bootstrap = User.query.count() == 0

    # Fuera del bootstrap, solo admins autenticados pueden crear usuarios
    if not is_bootstrap:
        if not current_user.is_authenticated:
            flash('Acceso restringido. Inicia sesion como administrador.', 'error')
            return redirect(url_for('auth.login'))
        if current_user.role != 'admin':
            flash('Solo los administradores pueden crear usuarios.', 'error')
            return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password')
        password2 = request.form.get('password2')

        # Validaciones
        if not all([username, email, password, password2]):
            flash('Por favor completa todos los campos', 'error')
            return render_template('auth/register.html', is_bootstrap=is_bootstrap)

        if len(username) < 3 or len(username) > 30:
            flash('El nombre de usuario debe tener entre 3 y 30 caracteres', 'error')
            return render_template('auth/register.html', is_bootstrap=is_bootstrap)

        import re
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            flash('El nombre de usuario solo puede contener letras, numeros y guion bajo', 'error')
            return render_template('auth/register.html', is_bootstrap=is_bootstrap)

        if password != password2:
            flash('Las contrasenas no coinciden', 'error')
            return render_template('auth/register.html', is_bootstrap=is_bootstrap)

        if len(password) < 8:
            flash('La contrasena debe tener al menos 8 caracteres', 'error')
            return render_template('auth/register.html', is_bootstrap=is_bootstrap)

        if User.query.filter_by(username=username).first():
            flash('El usuario ya existe', 'error')
            return render_template('auth/register.html', is_bootstrap=is_bootstrap)

        if User.query.filter_by(email=email).first():
            flash('El email ya esta registrado', 'error')
            return render_template('auth/register.html', is_bootstrap=is_bootstrap)

        # Bootstrap → primer admin; admin creando → rol elegido (analyst por defecto)
        if is_bootstrap:
            role = 'admin'
        else:
            from app.utils.auth import ROLE_HIERARCHY
            role = request.form.get('role', 'analyst')
            if role not in ROLE_HIERARCHY:
                role = 'analyst'

        user = User(username=username, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        from app.models.audit import AuditEvent
        AuditEvent.log('user_created', resource_type='user', resource_id=user.id,
                       details={'username': username, 'role': role}, _commit=True)

        if is_bootstrap:
            flash('Cuenta de administrador creada. Inicia sesion.', 'success')
            return redirect(url_for('auth.login'))

        flash(f'Usuario {username} creado con rol {role}.', 'success')
        return redirect(url_for('auth.register'))

    return render_template('auth/register.html', is_bootstrap=is_bootstrap)


@auth_bp.route('/profile')
@login_required
def profile():
    """Perfil del usuario"""
    return render_template('auth/profile.html', user=current_user)


@auth_bp.route('/change-password', methods=['POST'])
@login_required
@limiter.limit("5 per hour", methods=["POST"])
def change_password():
    """Cambiar contrasena del usuario"""
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    new_password2 = request.form.get('new_password2')

    if not all([current_password, new_password, new_password2]):
        flash('Completa todos los campos', 'error')
        return redirect(url_for('auth.profile'))

    if not current_user.check_password(current_password):
        flash('Contrasena actual incorrecta', 'error')
        return redirect(url_for('auth.profile'))

    if new_password != new_password2:
        flash('Las nuevas contrasenas no coinciden', 'error')
        return redirect(url_for('auth.profile'))

    if len(new_password) < 8:
        flash('La nueva contrasena debe tener al menos 8 caracteres', 'error')
        return redirect(url_for('auth.profile'))

    current_user.set_password(new_password)
    db.session.commit()

    flash('Contrasena actualizada correctamente', 'success')
    return redirect(url_for('auth.profile'))