"""
Regresión de los hallazgos MEDIOS de seguridad de full-audit-report.md (2026-11-13):
  * Logout por GET (logout CSRF con <img src="/auth/logout">)
  * Timing en login (enumeración de usuarios por latencia)
  * Sin bloqueo de cuenta (credential stuffing distribuido)
  * ALLOWED_HOSTS declarado pero sin validar (Host Header Poisoning)
  * Dependencias con CVEs conocidos (requirements.txt)
  * .env.example sugería SQLite (no funciona)
"""
import re
import statistics
import time
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from app.models.audit import AuditEvent
from app.utils.hosts import host_allowed, split_host
from app.utils.login_throttle import (
    LOCKOUT_THRESHOLD, LOCKOUT_WINDOW, MAX_USERNAME_LEN, lockout_remaining, minutes_left, normalize_username,
)
from app.utils.time_utils import utcnow

ROOT = Path(__file__).resolve().parents[2]


def _login(client, username, password):
    return client.post('/auth/login', data={'username': username, 'password': password})


def _event(db_session, action, username, *, minutes_ago=0, success=False):
    """Inserta un evento de auditoría con una antigüedad controlada."""
    ev = AuditEvent(action=action, success=success, created_at=utcnow() - timedelta(minutes=minutes_ago),
                    details={'username': username} if action in ('login_failed', 'login_blocked') else None,
                    username=username if action == 'login' else None)
    db_session.session.add(ev)
    db_session.session.commit()


# ============================================================================ LOGOUT

class TestLogoutSoloPost:
    def test_get_ya_no_cierra_la_sesion(self, analyst_client):
        r = analyst_client.get('/auth/logout')
        assert r.status_code == 405
        assert analyst_client.get('/dashboard').status_code == 200      # sigue autenticado

    def test_img_src_logout_no_funciona(self, analyst_client):
        """El ataque clásico: <img src="/auth/logout"> en otra página hace un GET."""
        assert analyst_client.get('/auth/logout', headers={'Referer': 'http://evil.example/'}).status_code == 405
        assert analyst_client.get('/dashboard').status_code == 200

    def test_post_cierra_la_sesion_y_audita(self, app, db_session, analyst_client, analyst_user):
        r = analyst_client.post('/auth/logout')
        assert r.status_code == 302
        assert analyst_client.get('/dashboard').status_code == 302      # ya no autenticado
        assert AuditEvent.query.filter_by(action='logout', resource_id=analyst_user.id).count() == 1

    def test_post_exige_token_csrf(self, app, analyst_client):
        app.config['WTF_CSRF_ENABLED'] = True
        try:
            assert analyst_client.post('/auth/logout').status_code == 400          # sin token
            html = analyst_client.get('/dashboard').get_data(as_text=True)
            token = re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)
            assert analyst_client.post('/auth/logout', headers={'X-CSRFToken': token}).status_code == 302
        finally:
            app.config['WTF_CSRF_ENABLED'] = False

    def test_la_barra_superior_usa_un_formulario_post_con_csrf(self, analyst_client):
        html = analyst_client.get('/dashboard').get_data(as_text=True)
        form = re.search(r'<form method="post" action="/auth/logout"[^>]*>(.*?)</form>', html, re.S)
        assert form, 'falta el formulario de logout'
        assert 'name="csrf_token"' in form.group(1)
        assert 'href="/auth/logout"' not in html

    def test_ninguna_plantilla_enlaza_logout_por_get(self):
        for path in (ROOT / 'app' / 'templates').rglob('*.html'):
            html = path.read_text(encoding='utf-8')
            assert not re.search(r'<a\b[^>]*url_for\(\'auth\.logout\'\)', html), path.name


# ============================================================================ TIMING

class TestTimingDeLogin:
    def test_usuario_inexistente_tambien_hashea(self, app, client):
        import app.routes.auth as auth_mod
        auth_mod._dummy_hash = None
        with patch.object(auth_mod, 'check_password_hash', wraps=auth_mod.check_password_hash) as chk:
            _login(client, 'no_existe_nadie', 'cualquiera123')
        assert chk.call_count == 1                       # hizo un hash real de relleno

    def test_usuario_existente_no_usa_el_hash_de_relleno(self, app, client, analyst_user):
        import app.routes.auth as auth_mod
        with patch.object(auth_mod, 'check_password_hash') as chk:
            _login(client, 'test_analyst', 'mala-contrasena')
        chk.assert_not_called()                          # usa User.check_password

    def test_la_latencia_no_distingue_existente_de_inexistente(self, app, client, analyst_user):
        """
        Antes: inexistente ~0.5 ms vs existente ~80 ms (ratio ~0.01). Margen amplio para no ser
        flaky: basta que el inexistente cueste al menos el 40% del existente.
        """
        def medir(user):
            t = []
            for _ in range(4):
                s = time.perf_counter()
                _login(client, user, 'contrasena-incorrecta-123')
                t.append(time.perf_counter() - s)
            return statistics.median(t)

        _login(client, 'warmup', 'x' * 12)                # calienta el hash de relleno
        existente = medir('test_analyst')
        inexistente = medir('usuario_que_no_existe_jamas')
        assert inexistente >= 0.4 * existente, (inexistente, existente)

    def test_el_mensaje_de_error_es_identico(self, client, analyst_user):
        a = _login(client, 'test_analyst', 'mala-mala-mala').get_data(as_text=True)
        b = _login(client, 'no_existe_nadie', 'mala-mala-mala').get_data(as_text=True)
        msg = 'Usuario o contraseña incorrectos'
        assert msg in a and msg in b


# ============================================================================ LOCKOUT

class TestBloqueoDeCuenta:
    def test_cinco_fallos_bloquean_aunque_la_contrasena_sea_correcta(self, app, client, analyst_user):
        for _ in range(LOCKOUT_THRESHOLD):
            assert _login(client, 'test_analyst', 'incorrecta-incorrecta').status_code == 200
        r = _login(client, 'test_analyst', 'AnalystPass123!')           # la correcta
        assert r.status_code == 429
        assert 'Demasiados intentos fallidos' in r.get_data(as_text=True)
        assert client.get('/dashboard').status_code == 302              # NO inició sesión

    def test_cuatro_fallos_no_bloquean(self, client, analyst_user):
        for _ in range(LOCKOUT_THRESHOLD - 1):
            _login(client, 'test_analyst', 'incorrecta-incorrecta')
        assert _login(client, 'test_analyst', 'AnalystPass123!').status_code == 302

    def test_el_bloqueo_aplica_igual_a_usuarios_inexistentes(self, client):
        """Si solo se bloquearan cuentas reales, el bloqueo revelaría qué usuarios existen."""
        for _ in range(LOCKOUT_THRESHOLD):
            _login(client, 'fantasma', 'x' * 10)
        r = _login(client, 'fantasma', 'x' * 10)
        assert r.status_code == 429 and 'Demasiados intentos fallidos' in r.get_data(as_text=True)

    def test_es_por_cuenta_no_por_ip(self, client, analyst_user, other_user):
        for _ in range(LOCKOUT_THRESHOLD):
            _login(client, 'test_analyst', 'incorrecta-incorrecta')
        assert _login(client, 'other_analyst', 'OtherPass123!').status_code == 302   # otra cuenta, misma IP

    def test_ignora_mayusculas_y_espacios(self, client, analyst_user):
        for u in ('test_analyst', 'TEST_ANALYST', ' Test_Analyst ', 'test_analyst', 'TeSt_AnAlYsT'):
            _login(client, u, 'incorrecta-incorrecta')
        assert _login(client, 'test_analyst', 'AnalystPass123!').status_code == 429

    def test_intentos_durante_el_bloqueo_no_lo_prolongan(self, app, db_session, client, analyst_user):
        for _ in range(LOCKOUT_THRESHOLD):
            _login(client, 'test_analyst', 'incorrecta-incorrecta')
        for _ in range(8):
            assert _login(client, 'test_analyst', 'incorrecta-incorrecta').status_code == 429
        assert AuditEvent.query.filter_by(action='login_failed').count() == LOCKOUT_THRESHOLD
        assert AuditEvent.query.filter_by(action='login_blocked').count() == 8

    def test_login_correcto_reinicia_la_cuenta(self, client, analyst_user):
        for _ in range(LOCKOUT_THRESHOLD - 1):
            _login(client, 'test_analyst', 'incorrecta-incorrecta')
        assert _login(client, 'test_analyst', 'AnalystPass123!').status_code == 302
        client.post('/auth/logout')
        # tras el éxito vuelven a hacer falta 5 fallos nuevos
        for _ in range(LOCKOUT_THRESHOLD - 1):
            _login(client, 'test_analyst', 'incorrecta-incorrecta')
        assert _login(client, 'test_analyst', 'AnalystPass123!').status_code == 302


class TestVentanaDeslizante:
    def test_fallos_antiguos_no_cuentan(self, app, db_session):
        with app.app_context():
            for _ in range(LOCKOUT_THRESHOLD):
                _event(db_session, 'login_failed', 'viejo', minutes_ago=20)
            assert lockout_remaining('viejo') is None

    def test_el_bloqueo_expira_cuando_el_fallo_n_sale_de_la_ventana(self, app, db_session):
        with app.app_context():
            # 5 fallos hace 14, 10, 8, 5 y 1 min -> el 5º más reciente (14 min) sale en 1 min
            for m in (14, 10, 8, 5, 1):
                _event(db_session, 'login_failed', 'ana', minutes_ago=m)
            rem = lockout_remaining('ana')
            assert rem is not None
            assert timedelta(seconds=30) < rem <= timedelta(minutes=1, seconds=5)
            assert minutes_left(rem) == 1
            # 2 min más tarde ya no está bloqueada
            assert lockout_remaining('ana', now=utcnow() + timedelta(minutes=2)) is None

    def test_el_bloqueo_maximo_dura_la_ventana(self, app, db_session):
        with app.app_context():
            for _ in range(LOCKOUT_THRESHOLD):
                _event(db_session, 'login_failed', 'bob', minutes_ago=0)
            rem = lockout_remaining('bob')
            assert LOCKOUT_WINDOW - timedelta(seconds=10) < rem <= LOCKOUT_WINDOW

    def test_un_login_correcto_posterior_reinicia(self, app, db_session):
        with app.app_context():
            for m in (9, 8, 7, 6):
                _event(db_session, 'login_failed', 'cara', minutes_ago=m)
            _event(db_session, 'login', 'cara', minutes_ago=5, success=True)
            _event(db_session, 'login_failed', 'cara', minutes_ago=1)
            assert lockout_remaining('cara') is None                    # solo cuenta 1 fallo

    def test_no_mezcla_usuarios(self, app, db_session):
        with app.app_context():
            for _ in range(LOCKOUT_THRESHOLD):
                _event(db_session, 'login_failed', 'uno')
            assert lockout_remaining('uno') is not None
            assert lockout_remaining('dos') is None

    @pytest.mark.parametrize('valor', [None, '', '   '])
    def test_username_vacio_no_bloquea(self, app, valor):
        with app.app_context():
            assert lockout_remaining(valor) is None

    def test_normalize_y_truncado(self):
        assert normalize_username('  AbC ') == 'abc'
        assert len(normalize_username('x' * 10_000)) == MAX_USERNAME_LEN

    def test_username_enorme_no_infla_la_auditoria(self, app, db_session, client):
        _login(client, 'A' * 50_000, 'whatever-123')
        ev = AuditEvent.query.filter_by(action='login_failed').one()
        assert len(ev.details['username']) == MAX_USERNAME_LEN


# ============================================================================ ALLOWED_HOSTS

class TestHostPermitido:
    @pytest.mark.parametrize('host,allowed,esperado', [
        ('localhost', ['127.0.0.1', 'localhost'], True),
        ('localhost:5000', ['127.0.0.1', 'localhost'], True),
        ('127.0.0.1:5055', ['127.0.0.1', 'localhost'], True),
        ('LOCALHOST', ['localhost'], True),
        ('evil.com', ['127.0.0.1', 'localhost'], False),
        ('localhost.evil.com', ['localhost'], False),            # sufijo/prefijo engañoso
        ('evil.com#localhost', ['localhost'], False),
        ('localhost@evil.com', ['localhost'], False),
        ('localhost/evil', ['localhost'], False),
        ('local host', ['*'], False),                            # malformado: ni con '*'
        ('', ['localhost'], False),
        (None, ['localhost'], False),
        ('[::1]:5000', ['::1'], True),
        ('[::1]', ['[::1]'], True),
        ('a.example.com', ['.example.com'], True),
        ('x.y.example.com:443', ['.example.com'], True),
        ('example.com', ['.example.com'], True),
        ('badexample.com', ['.example.com'], False),             # no es subdominio
        ('example.com.evil.com', ['.example.com'], False),
        ('cualquiera.test', ['*'], True),
        ('x.test', [], False),
        ('x.test', None, False),
    ])
    def test_tabla(self, host, allowed, esperado):
        assert host_allowed(host, allowed) is esperado

    def test_split_host(self):
        assert split_host('A.com:80') == 'a.com'
        assert split_host('[::1]:5000') == '::1'
        assert split_host('::1') == '::1'


@pytest.fixture
def sin_server_name(app):
    """conftest fija SERVER_NAME='localhost'; con otros hosts Flask responde 404 al enrutar. En
    produccion SERVER_NAME no se define, asi que para probar hosts permitidos se desactiva."""
    old = app.config.get('SERVER_NAME')
    app.config['SERVER_NAME'] = None
    yield
    app.config['SERVER_NAME'] = old


class TestHostEnLaApp:
    def test_host_no_permitido_da_400(self, client):
        r = client.get('/auth/login', base_url='http://evil.com')
        assert r.status_code == 400 and r.get_data(as_text=True) == 'Invalid Host header'

    def test_host_permitido_pasa(self, client, sin_server_name):
        assert client.get('/auth/login').status_code == 200                       # localhost
        assert client.get('/auth/login', base_url='http://localhost:5000').status_code == 200

    def test_aplica_a_la_api_y_a_los_estaticos(self, client):
        assert client.get('/api/v2/health', base_url='http://evil.com').status_code == 400
        assert client.get('/static/ui-actions.js', base_url='http://evil.com').status_code == 400

    def test_la_configuracion_se_respeta(self, app, client, sin_server_name):
        old = app.config['ALLOWED_HOSTS']
        app.config['ALLOWED_HOSTS'] = ['soc.example.com']
        try:
            assert client.get('/auth/login', base_url='http://soc.example.com').status_code == 200
            assert client.get('/auth/login').status_code == 400                   # localhost ya no
        finally:
            app.config['ALLOWED_HOSTS'] = old

    def test_lista_vacia_desactiva_la_validacion(self, app, client, sin_server_name):
        old = app.config['ALLOWED_HOSTS']
        app.config['ALLOWED_HOSTS'] = []
        try:
            assert client.get('/auth/login', base_url='http://lo.que.sea').status_code == 200
        finally:
            app.config['ALLOWED_HOSTS'] = old

    def test_se_valida_antes_que_el_login(self, client, analyst_user):
        r = client.post('/auth/login', data={'username': 'test_analyst', 'password': 'AnalystPass123!'},
                        base_url='http://evil.com')
        assert r.status_code == 400
        assert AuditEvent.query.filter_by(action='login').count() == 0

    def test_el_rechazo_conserva_los_headers_de_seguridad(self, client):
        r = client.get('/', base_url='http://evil.com')
        assert r.status_code == 400 and 'Content-Security-Policy' in r.headers

    def test_produccion_avisa_si_falta_allowed_hosts(self, monkeypatch, caplog):
        from app.config import ProductionConfig
        monkeypatch.setenv('SECRET_KEY', 'x' * 40)
        monkeypatch.setenv('DATABASE_URL', 'postgresql://u:p@h/d')
        monkeypatch.setenv('AUDIT_CHAIN_KEY', 'k' * 32)
        monkeypatch.delenv('ALLOWED_HOSTS', raising=False)
        with caplog.at_level('WARNING'):
            ProductionConfig.init_app(None)
        assert 'ALLOWED_HOSTS no esta definido' in caplog.text

    def test_produccion_no_avisa_si_esta_definido(self, monkeypatch, caplog):
        from app.config import ProductionConfig
        monkeypatch.setenv('SECRET_KEY', 'x' * 40)
        monkeypatch.setenv('DATABASE_URL', 'postgresql://u:p@h/d')
        monkeypatch.setenv('AUDIT_CHAIN_KEY', 'k' * 32)
        monkeypatch.setenv('ALLOWED_HOSTS', 'soc.example.com')
        with caplog.at_level('WARNING'):
            ProductionConfig.init_app(None)
        assert 'ALLOWED_HOSTS no esta definido' not in caplog.text


class TestConfiguracionDeDespliegue:
    def test_compose_pasa_allowed_hosts(self):
        compose = (ROOT / 'docker-compose.yml').read_text(encoding='utf-8')
        assert 'ALLOWED_HOSTS=${ALLOWED_HOSTS:-127.0.0.1,localhost}' in compose

    def test_env_example_documenta_allowed_hosts_y_no_sugiere_sqlite(self):
        env = (ROOT / '.env.example').read_text(encoding='utf-8')
        assert re.search(r'^ALLOWED_HOSTS=', env, re.M)
        assert not re.search(r'^#?\s*DATABASE_URL=sqlite', env, re.M)
        assert 'SQLite NO funciona' in env


# ============================================================================ DEPENDENCIAS

def _requirement(name):
    for line in (ROOT / 'requirements.txt').read_text(encoding='utf-8').splitlines():
        m = re.match(rf'^{re.escape(name)}(\[[^\]]+\])?\s*(==|>=)\s*([0-9][^,\s#<]*)', line, re.I)
        if m:
            return m.group(2), tuple(int(x) for x in re.findall(r'\d+', m.group(3))[:3])
    raise AssertionError(f'{name} no esta en requirements.txt')


class TestDependenciasSinCvesConocidos:
    """Mínimos verificados contra OSV (api.osv.dev) el 2026-11-13."""

    @pytest.mark.parametrize('nombre,minimo', [
        ('Flask', (3, 1, 3)),            # CVE-2026-27205
        ('python-dotenv', (1, 2, 2)),    # CVE-2026-28684
        ('cryptography', (48, 0, 1)),    # CVE-2023-50782, CVE-2024-0727, CVE-2024-26130, OpenSSL embebido
        ('requests', (2, 33, 0)),        # CVE-2024-47081, CVE-2026-25645
        ('sentry-sdk', (1, 45, 1)),      # CVE-2024-40647
        ('gunicorn', (22, 0, 0)),        # CVE-2024-1135, CVE-2024-6827 (request smuggling)
    ])
    def test_version_minima(self, nombre, minimo):
        _, version = _requirement(nombre)
        assert version >= minimo, f'{nombre} {version} < {minimo}'

    def test_flask_esta_fijado_exactamente(self):
        assert _requirement('Flask')[0] == '=='


class TestRequirementsReproducibles:
    """
    Hallazgos de la instalacion LIMPIA desde requirements.txt (entorno virtual nuevo, 2026-11-13):
    el entorno conda de desarrollo estaba desfasado y ocultaba dos fallos que habrian roto la
    imagen Docker (que hace `pip install -r requirements.txt` sin versiones fijas de lo transitivo).
    """

    def _lines(self):
        return (ROOT / 'requirements.txt').read_text(encoding='utf-8').splitlines()

    def test_sqlalchemy_tiene_tope_menor_que_2_1(self):
        """SQLAlchemy 2.1 cambia el driver por defecto de postgresql:// a psycopg (v3); la app usa
        psycopg2-binary -> "No module named 'psycopg'" al arrancar."""
        linea = next(l for l in self._lines() if re.match(r'^SQLAlchemy', l, re.I))
        assert '<2.1' in linea.replace(' ', '')

    def test_tzdata_esta_declarado(self):
        """ZoneInfo('America/Mexico_City') necesita tzdata en Windows y en imagenes sin zoneinfo."""
        assert any(re.match(r'^tzdata', l, re.I) for l in self._lines())

    def test_no_se_fija_una_version_yanked(self):
        assert not any(re.match(r'^email-validator\s*==\s*2\.1\.0', l, re.I) for l in self._lines())

    def test_el_dockerfile_instala_desde_requirements(self):
        assert 'pip install --no-cache-dir -r requirements.txt' in (ROOT / 'Dockerfile').read_text(encoding='utf-8')
