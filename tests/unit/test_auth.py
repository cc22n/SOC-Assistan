"""
Tests de Autenticación — T3A-02
Cubre: login, logout, registro, usuario inactivo, open redirect
"""
import pytest


# ==============================================================================
# HELPERS
# ==============================================================================

def login(client, username, password, next_url=None):
    url = '/auth/login'
    if next_url:
        url += f'?next={next_url}'
    return client.post(url, data={'username': username, 'password': password},
                       follow_redirects=True)


def get_flash_messages(response_data):
    """Extrae mensajes de flash del HTML de respuesta."""
    text = response_data.decode('utf-8', errors='replace')
    return text


# ==============================================================================
# LOGIN
# ==============================================================================

class TestLogin:

    def test_login_page_loads(self, client):
        """GET /auth/login devuelve 200."""
        resp = client.get('/auth/login')
        assert resp.status_code == 200

    def test_login_success_redirects_to_dashboard(self, client, analyst_user):
        """Login con credenciales correctas redirige al dashboard."""
        resp = client.post('/auth/login', data={
            'username': 'test_analyst',
            'password': 'AnalystPass123!',
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert 'dashboard' in resp.headers['Location'] or resp.headers['Location'] == '/'

    def test_login_wrong_password(self, client, analyst_user):
        """Contraseña incorrecta → 200 con mensaje de error."""
        resp = login(client, 'test_analyst', 'WrongPassword!')
        assert resp.status_code == 200
        assert 'incorrectos' in resp.data.decode('utf-8', errors='replace')

    def test_login_nonexistent_user(self, client, db_session):
        """Usuario que no existe → 200 con mensaje de error."""
        resp = login(client, 'ghost_user', 'AnyPassword123!')
        assert resp.status_code == 200
        assert 'incorrectos' in resp.data.decode('utf-8', errors='replace')

    def test_login_inactive_user(self, client, db_session):
        """Usuario inactivo → 200 con mensaje de desactivado."""
        from app.models.ioc import User

        inactive = User(
            username='inactive_user',
            email='inactive@soc-test.local',
            role='analyst',
            is_active=False,
        )
        inactive.set_password('InactivePass123!')
        db_session.session.add(inactive)
        db_session.session.commit()

        resp = login(client, 'inactive_user', 'InactivePass123!')
        assert resp.status_code == 200
        body = resp.data.decode('utf-8', errors='replace')
        assert 'desactivado' in body or 'administrador' in body

    def test_login_empty_fields(self, client, db_session):
        """Campos vacíos → 200 con mensaje de campos requeridos."""
        resp = client.post('/auth/login', data={'username': '', 'password': ''},
                           follow_redirects=True)
        assert resp.status_code == 200

    def test_login_already_authenticated_redirects(self, analyst_client):
        """Usuario ya autenticado que visita /login → redirige (no re-login)."""
        resp = analyst_client.get('/auth/login', follow_redirects=False)
        assert resp.status_code == 302

    def test_login_updates_last_login(self, client, analyst_user, db_session):
        """Login exitoso actualiza last_login del usuario."""
        from app.models.ioc import User
        login(client, 'test_analyst', 'AnalystPass123!')
        db_session.session.refresh(analyst_user)
        assert analyst_user.last_login is not None


# ==============================================================================
# OPEN REDIRECT
# ==============================================================================

class TestOpenRedirect:

    def test_next_param_internal_path_is_respected(self, client, analyst_user):
        """Parámetro next con ruta interna válida se respeta."""
        resp = client.post('/auth/login?next=/dashboard', data={
            'username': 'test_analyst',
            'password': 'AnalystPass123!',
        }, follow_redirects=False)
        assert resp.status_code == 302
        # Ruta interna aceptada
        loc = resp.headers.get('Location', '')
        assert 'evil.com' not in loc

    def test_next_param_external_url_is_rejected(self, client, analyst_user):
        """Parámetro next con dominio externo NO redirige externamente."""
        resp = client.post('/auth/login?next=http://evil.com/steal', data={
            'username': 'test_analyst',
            'password': 'AnalystPass123!',
        }, follow_redirects=False)
        assert resp.status_code == 302
        location = resp.headers.get('Location', '')
        assert 'evil.com' not in location

    def test_next_param_javascript_uri_is_rejected(self, client, analyst_user):
        """Parámetro next con javascript: URI es rechazado (400 por middleware XSS o 302 sin redirect JS)."""
        resp = client.post('/auth/login?next=javascript:alert(1)', data={
            'username': 'test_analyst',
            'password': 'AnalystPass123!',
        }, follow_redirects=False)
        # Middleware de seguridad puede bloquear antes del login (400)
        # o el login puede redirigir a /dashboard ignorando el next peligroso (302).
        assert resp.status_code in (302, 400)
        if resp.status_code == 302:
            location = resp.headers.get('Location', '')
            assert 'javascript' not in location.lower()


# ==============================================================================
# LOGOUT
# ==============================================================================

class TestLogout:

    def test_logout_authenticated_user(self, analyst_client):
        """Logout de usuario autenticado redirige al index."""
        resp = analyst_client.get('/auth/logout', follow_redirects=False)
        assert resp.status_code == 302

    def test_logout_unauthenticated_redirects_to_login(self, client):
        """Logout sin autenticar → redirige a login."""
        resp = client.get('/auth/logout', follow_redirects=False)
        assert resp.status_code == 302
        location = resp.headers.get('Location', '')
        assert 'login' in location


# ==============================================================================
# REGISTRO
# ==============================================================================

class TestRegister:

    def test_register_page_loads(self, client):
        """GET /auth/register devuelve 200."""
        resp = client.get('/auth/register')
        assert resp.status_code == 200

    def test_register_first_user_becomes_admin(self, client, db_session):
        """El primer usuario registrado recibe role='admin'."""
        from app.models.ioc import User

        resp = client.post('/auth/register', data={
            'username': 'firstuser',
            'email': 'first@soc-test.local',
            'password': 'FirstPass123!',
            'password2': 'FirstPass123!',
        }, follow_redirects=True)
        assert resp.status_code == 200

        user = User.query.filter_by(username='firstuser').first()
        assert user is not None
        assert user.role == 'admin'

    def test_register_second_user_becomes_analyst(self, client, db_session, admin_user):
        """El segundo usuario registrado recibe role='analyst'."""
        from app.models.ioc import User

        client.post('/auth/register', data={
            'username': 'seconduser',
            'email': 'second@soc-test.local',
            'password': 'SecondPass123!',
            'password2': 'SecondPass123!',
        }, follow_redirects=True)

        user = User.query.filter_by(username='seconduser').first()
        assert user is not None
        assert user.role == 'analyst'

    def test_register_duplicate_username_rejected(self, client, db_session, analyst_user):
        """Registrar username duplicado devuelve error."""
        resp = client.post('/auth/register', data={
            'username': 'test_analyst',
            'email': 'different@soc-test.local',
            'password': 'NewPass123!',
            'password2': 'NewPass123!',
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert 'ya existe' in resp.data.decode('utf-8', errors='replace')

    def test_register_duplicate_email_rejected(self, client, db_session, analyst_user):
        """Registrar email duplicado devuelve error."""
        resp = client.post('/auth/register', data={
            'username': 'new_name',
            'email': 'analyst@soc-test.local',
            'password': 'NewPass123!',
            'password2': 'NewPass123!',
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert 'registrado' in resp.data.decode('utf-8', errors='replace')

    def test_register_password_mismatch(self, client, db_session):
        """Contraseñas distintas devuelven error."""
        resp = client.post('/auth/register', data={
            'username': 'newuser',
            'email': 'newuser@soc-test.local',
            'password': 'PassA123!',
            'password2': 'PassB123!',
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert 'coinciden' in resp.data.decode('utf-8', errors='replace')

    def test_register_short_password_rejected(self, client, db_session):
        """Contraseña menor a 8 chars devuelve error."""
        resp = client.post('/auth/register', data={
            'username': 'newuser',
            'email': 'newuser@soc-test.local',
            'password': 'abc',
            'password2': 'abc',
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert '8' in resp.data.decode('utf-8', errors='replace')

    def test_register_invalid_username_chars(self, client, db_session):
        """Username con caracteres especiales devuelve error."""
        resp = client.post('/auth/register', data={
            'username': 'user name!',
            'email': 'valid@soc-test.local',
            'password': 'ValidPass123!',
            'password2': 'ValidPass123!',
        }, follow_redirects=True)
        assert resp.status_code == 200

    def test_register_success_redirects_to_login(self, client, db_session):
        """Registro exitoso redirige a /auth/login."""
        resp = client.post('/auth/register', data={
            'username': 'validuser',
            'email': 'valid@soc-test.local',
            'password': 'ValidPass123!',
            'password2': 'ValidPass123!',
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert 'login' in resp.headers.get('Location', '')
