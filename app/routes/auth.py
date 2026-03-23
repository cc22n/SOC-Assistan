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
            flash('Usuario o contraseña incorrectos', 'error')
            return render_template('auth/login.html')

        if not user.is_active:
            flash('Usuario desactivado. Contacta al administrador', 'error')
            return render_template('auth/login.html')

        login_user(user, remember=remember)

        # Actualizar last_login
        from datetime import datetime
        user.last_login = datetime.utcnow()
        db.session.commit()

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
    logout_user()
    flash('Sesión cerrada correctamente', 'info')
    return redirect(url_for('main.index'))


@auth_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per minute", methods=["POST"])
def register():
    """Registro de nuevo usuario"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password')
        password2 = request.form.get('password2')

        # Validaciones
        if not all([username, email, password, password2]):
            flash('Por favor completa todos los campos', 'error')
            return render_template('auth/register.html')

        if len(username) < 3 or len(username) > 30:
            flash('El nombre de usuario debe tener entre 3 y 30 caracteres', 'error')
            return render_template('auth/register.html')

        import re
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            flash('El nombre de usuario solo puede contener letras, numeros y guion bajo', 'error')
            return render_template('auth/register.html')

        if password != password2:
            flash('Las contrasenas no coinciden', 'error')
            return render_template('auth/register.html')

        if len(password) < 8:
            flash('La contrasena debe tener al menos 8 caracteres', 'error')
            return render_template('auth/register.html')

        if User.query.filter_by(username=username).first():
            flash('El usuario ya existe', 'error')
            return render_template('auth/register.html')

        if User.query.filter_by(email=email).first():
            flash('El email ya esta registrado', 'error')
            return render_template('auth/register.html')

        # Primer usuario = admin, resto = analyst
        is_first = User.query.count() == 0
        user = User(
            username=username,
            email=email,
            role='admin' if is_first else 'analyst'
        )
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        role_msg = ' (Administrador)' if is_first else ''
        flash(f'Cuenta creada exitosamente{role_msg}. Inicia sesion.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html')


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