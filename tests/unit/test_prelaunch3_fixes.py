"""
Correcciones del informe de pre-lanzamiento 3 (prelaunch-report-3.md), verificadas una a una antes de actuar:

  1. Rol de BD sin privilegios (la app NO se conecta como superusuario) y sin contraseña pública por defecto en compose.
  2. restore_db.sh: un error a mitad no puede dejar la BD a medias ni imprimir "éxito".
  3. Sentry guardaba el token de Telegram (y claves de query) en los breadcrumbs. REPRODUCIDO antes de corregir.
  4. Clave de la cadena de auditoría perdida: procedimiento (en test_audit_chain.py, TestRotacion) y documentación.
"""
import gzip
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from sqlalchemy import text

from app import db
from app.utils import sentry_scrub
from app.utils.db_roles import MIN_PASSWORD_LEN, ensure_app_role

ROOT = Path(__file__).resolve().parents[2]
TOKEN = '123456789:AAFAKE_tokenSecretoQueNoDebeFiltrarse_xyz'


def _bash():
    import shutil
    if sys.platform == 'win32':
        for p in ('C:/Program Files/Git/bin/bash.exe', 'C:/Program Files (x86)/Git/bin/bash.exe'):
            if Path(p).exists():
                return p
        pytest.skip('no hay Git Bash: en Windows el `bash` del PATH suele ser el de WSL')
    return shutil.which('bash') or pytest.skip('no hay bash')




# ============================================================================ 3. SENTRY

class TestSentryScrub:
    @pytest.mark.parametrize('texto', [
        f'https://api.telegram.org/bot{TOKEN}/sendMessage', f'POST /bot{TOKEN}/getMe', f'token en claro {TOKEN}',
    ])
    def test_quita_el_token_de_telegram(self, texto):
        assert TOKEN not in sentry_scrub.scrub(texto)

    @pytest.mark.parametrize('qs', ['apiKey=SECRETO123', 'apikey=SECRETO123', 'api_key=SECRETO123', 'token=SECRETO123', 'key=SECRETO123',
                                    'access_token=SECRETO123', 'password=SECRETO123', 'secret=SECRETO123', 'signature=SECRETO123'])
    def test_quita_claves_en_la_query(self, qs):
        out = sentry_scrub.scrub(f'https://api.ejemplo.com/v1/x?ip=1.2.3.4&{qs}&otro=ok')
        assert 'SECRETO123' not in out and 'ip=1.2.3.4' in out and 'otro=ok' in out          # lo demás se conserva

    def test_valores_de_claves_sensibles_en_diccionarios(self):
        out = sentry_scrub.scrub({'headers': {'Authorization': 'Bearer abc', 'X-Api-Key': 'k', 'Accept': 'json'}, 'cookie': 'sid=1',
                                  'data': {'password': 'p', 'q': 'ok'}})
        assert out['headers']['Authorization'] == out['headers']['X-Api-Key'] == out['cookie'] == out['data']['password'] == '<REDACTED>'
        assert out['headers']['Accept'] == 'json' and out['data']['q'] == 'ok'

    def test_recursivo_y_tolera_cualquier_tipo(self):
        out = sentry_scrub.scrub({'a': [{'u': f'/bot{TOKEN}/x'}, (f'{TOKEN}',)], 'n': 5, 'none': None, 'f': 1.5, 'b': True})
        assert TOKEN not in str(out) and out['n'] == 5 and out['none'] is None and out['b'] is True

    def test_control_texto_normal_intacto(self):
        txt = {'message': 'IOC 8.8.8.8 analizado en 120 ms', 'category': 'httplib', 'level': 'info'}
        assert sentry_scrub.scrub(txt) == txt

    def test_con_el_sdk_real_el_token_no_llega_al_breadcrumb(self):
        """Con el SDK de verdad: SIN los filtros el token queda guardado (control: el hallazgo era real); CON ellos, no."""
        import sentry_sdk

        def breadcrumbs():
            sc = sentry_sdk.get_current_scope() if hasattr(sentry_sdk, 'get_current_scope') else sentry_sdk.Hub.current.scope
            return list(getattr(sc, '_breadcrumbs', []))

        def clear():
            sc = sentry_sdk.get_current_scope() if hasattr(sentry_sdk, 'get_current_scope') else sentry_sdk.Hub.current.scope
            sc.clear_breadcrumbs()

        crumb = dict(category='httplib', message=f'POST https://api.telegram.org/bot{TOKEN}/sendMessage',
                     data={'url': f'https://api.telegram.org/bot{TOKEN}/sendMessage', 'http.query': 'apiKey=SECRETO123'})
        try:
            sentry_sdk.init(dsn='https://k@o0.ingest.sentry.io/1', before_send=lambda e, h: None)            # SIN filtros
            clear()
            sentry_sdk.add_breadcrumb(**crumb)
            assert TOKEN in str(breadcrumbs()) and 'SECRETO123' in str(breadcrumbs())                           # CONTROL: se filtraba

            kw = sentry_scrub.sentry_init_kwargs('https://k@o0.ingest.sentry.io/1')
            kw['before_send'] = lambda e, h: None                                                               # sin red en el test
            sentry_sdk.init(**kw)                                                                               # CON filtros
            clear()
            sentry_sdk.add_breadcrumb(**crumb)
            assert breadcrumbs() and TOKEN not in str(breadcrumbs()) and 'SECRETO123' not in str(breadcrumbs())
        finally:
            sentry_sdk.init()          # desactiva el cliente
            clear()

    def test_los_filtros_siempre_van_en_la_inicializacion(self):
        kw = sentry_scrub.sentry_init_kwargs('https://k@o0.ingest.sentry.io/1')
        assert kw['before_breadcrumb'] is sentry_scrub.before_breadcrumb and kw['before_send'] is sentry_scrub.before_send
        assert kw['send_default_pii'] is False

    def test_la_app_inicializa_sentry_solo_por_ese_camino(self):
        src = (ROOT / 'app' / '__init__.py').read_text(encoding='utf-8')
        assert 'sentry_sdk.init(**sentry_init_kwargs(' in src
        assert len(re.findall(r'sentry_sdk\.init\(', src)) == 1                  # ninguna otra inicialización sin filtros


# ============================================================================ 1. ROL SIN PRIVILEGIOS

class TestRolDeLaApp:
    def test_validaciones_sin_tocar_la_bd(self, app):
        with app.app_context():
            for malo in ('', 'Soc App', 'soc-app', '1app', 'a' * 64, 'x;DROP TABLE users'):
                with pytest.raises(ValueError, match='APP_DB_USER'):
                    ensure_app_role(db.engine, malo, 'p' * 20)
            for corta in (None, '', 'x' * (MIN_PASSWORD_LEN - 1)):
                with pytest.raises(ValueError, match='APP_DB_PASSWORD'):
                    ensure_app_role(db.engine, 'soc_app_t', corta)

    def test_no_puede_ser_el_mismo_rol_que_migra(self, app):
        with app.app_context():
            admin = db.session.execute(text('SELECT current_user')).scalar()
            db.session.rollback()
            with pytest.raises(ValueError, match='mismo rol'):
                ensure_app_role(db.engine, admin, 'p' * 20)

    def test_no_deja_la_conexion_del_pool_en_autocommit(self, app, db_session):
        """Regresión: la conexión devuelta al pool seguía en autocommit y el rollback de tests/consultas posteriores no deshacía nada."""
        from app.models.audit import AuditEvent
        admin = db.session.execute(text('SELECT current_user')).scalar()
        db.session.rollback()
        with pytest.raises(ValueError, match='mismo rol'):
            ensure_app_role(db.engine, admin, 'p' * 20)               # se conecta, pone autocommit y falla DESPUÉS
        AuditEvent.log('descartado')
        db.session.flush()
        db.session.rollback()
        assert AuditEvent.query.count() == 0                          # con la conexión en autocommit esto daba 1

    @pytest.fixture
    def privilegios(self, app):
        """Estas pruebas crean roles: exigen superusuario (en el CI lo es; en local `soc_admin` no, y entonces se omiten: lo cubre verify_docker.sh)."""
        with app.app_context():
            ok = db.session.execute(text('SELECT rolsuper OR rolcreaterole FROM pg_roles WHERE rolname = current_user')).scalar()
            db.session.rollback()
        if not ok:
            pytest.skip('el usuario de la BD de test no puede crear roles (en el CI sí): cubierto por scripts/ops/verify_docker.sh')

    @pytest.fixture
    def rol(self, app, privilegios, db_session):
        nombre = 'soc_app_pytest'
        yield nombre
        db.session.rollback()
        db.session.execute(text(f'DROP OWNED BY {nombre}'))
        db.session.execute(text(f'DROP ROLE IF EXISTS {nombre}'))
        db.session.commit()

    def _conectar(self, app, rol, password):
        import psycopg2
        u = db.engine.url
        return psycopg2.connect(host=u.host, port=u.port, dbname=u.database, user=rol, password=password, connect_timeout=5)

    def test_el_rol_creado_no_puede_apagar_el_trigger_ni_borrar_auditoria_ni_hacer_ddl(self, app, rol):
        from app.services import audit_chain as ac
        pw = 'x' * 24
        with app.app_context():
            db.session.execute(text(ac.GUARD_FUNCTION_SQL))
            db.session.execute(text('DROP TRIGGER IF EXISTS trg_audit_events_guard ON audit_events'))
            db.session.execute(text(ac.GUARD_TRIGGER_SQL))
            db.session.commit()
            info = ensure_app_role(db.engine, rol, pw)
            assert info['created'] is True and info['role'] == rol
            attrs = db.session.execute(text('SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls FROM pg_roles '
                                            'WHERE rolname = :r'), {'r': rol}).one()
            assert tuple(attrs) == (False, False, False, False, False)
        conn = self._conectar(app, rol, pw)
        conn.autocommit = True
        cur = conn.cursor()
        try:
            def falla(sql, *frases):
                with pytest.raises(Exception) as e:
                    cur.execute(sql)
                assert any(f in str(e.value).lower() for f in frases), str(e.value)

            cur.execute('SELECT count(*) FROM audit_events')                                 # CONTROL: lo que SÍ debe poder hacer
            cur.execute("INSERT INTO audit_events (action, success, created_at) VALUES ('t', true, now())")
            cur.execute('SELECT count(*) FROM users')
            falla('ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_guard', 'must be owner', 'debe ser')
            falla('DROP TRIGGER trg_audit_events_guard ON audit_events', 'must be owner', 'debe ser')
            falla('DELETE FROM audit_events', 'permission denied', 'permiso denegado')
            falla('TRUNCATE audit_events', 'permission denied', 'permiso denegado')
            falla('DROP TABLE users CASCADE', 'must be owner', 'debe ser')
            falla('CREATE TABLE intruso (x int)', 'permission denied', 'permiso denegado')
            falla('SELECT * FROM alembic_version', 'permission denied', 'permiso denegado')
            falla('CREATE ROLE otro LOGIN', 'permission denied', 'permiso denegado')
        finally:
            conn.close()

    def test_es_idempotente_y_sincroniza_la_contrasena(self, app, rol):
        with app.app_context():
            assert ensure_app_role(db.engine, rol, 'a' * 24)['created'] is True
            assert ensure_app_role(db.engine, rol, 'b' * 24)['created'] is False
        self._conectar(app, rol, 'b' * 24).close()                                          # la nueva contraseña vale
        with pytest.raises(Exception):
            self._conectar(app, rol, 'a' * 24)                                              # la antigua ya no


# ============================================================================ 1b. COMPOSE E INICIO

class TestComposeSinSecretosPublicos:
    @pytest.fixture(scope='class')
    def compose(self):
        return yaml.safe_load((ROOT / 'docker-compose.yml').read_text(encoding='utf-8'))

    @staticmethod
    def _env(svc):
        e = svc.get('environment') or []
        if isinstance(e, dict):
            return {k: str(v) for k, v in e.items()}
        return dict(x.split('=', 1) for x in e)

    def test_no_hay_contrasena_publica_por_defecto_en_ningun_archivo(self):
        for f in ('docker-compose.yml', '.env.example', 'docker/init_db.py', 'scripts/ops/backup_db.sh', 'scripts/ops/restore_db.sh',
                  'README.md', 'CLAUDE.md'):
            p = ROOT / f
            if p.exists():
                assert 'soc_secure_password' not in p.read_text(encoding='utf-8'), f

    def test_las_contrasenas_son_obligatorias(self, compose):
        db_env = self._env(compose['services']['db'])
        assert db_env['POSTGRES_PASSWORD'].startswith('${POSTGRES_PASSWORD:?')
        app_env = self._env(compose['services']['app'])
        assert app_env['APP_DB_PASSWORD'].startswith('${APP_DB_PASSWORD:?') and ':?' in app_env['MIGRATION_DATABASE_URL']

    def test_la_app_y_el_daemon_no_usan_al_administrador(self, compose):
        for nombre in ('app', 'feeds'):
            url = self._env(compose['services'][nombre])['DATABASE_URL']
            assert 'soc_admin' not in url and 'APP_DB_USER' in url, nombre
        assert 'soc_admin' in self._env(compose['services']['app'])['MIGRATION_DATABASE_URL']

    def test_el_daemon_no_recibe_las_credenciales_del_administrador(self, compose):
        env = self._env(compose['services']['feeds'])
        assert 'MIGRATION_DATABASE_URL' not in env and 'POSTGRES_PASSWORD' not in str(env)

    def test_init_db_fija_la_url_del_administrador_antes_de_importar_la_app(self):
        src = (ROOT / 'docker' / 'init_db.py').read_text(encoding='utf-8')
        assert src.index("os.environ['DATABASE_URL'] = os.environ['MIGRATION_DATABASE_URL']") < src.index('from app import create_app')
        assert 'ensure_app_role' in src and "'APP_DB_PASSWORD'" in src

    def test_las_variables_estan_documentadas(self):
        env = (ROOT / '.env.example').read_text(encoding='utf-8')
        for v in ('POSTGRES_PASSWORD=', 'APP_DB_PASSWORD=', 'APP_DB_USER=', 'AUDIT_CHAIN_LOST_KEY_IDS='):
            assert v in env
        assert not any(re.match(r'(POSTGRES_PASSWORD|APP_DB_PASSWORD)=.+', l) for l in env.splitlines())   # sin valores reales

    def test_verify_docker_prueba_el_rol_y_el_restore(self):
        v = (ROOT / 'scripts' / 'ops' / 'verify_docker.sh').read_text(encoding='utf-8')
        for frag in ('soc_app no es superusuario', 'NO puede apagar el trigger', 'backup_db.sh', 'restore_db.sh', 'NO imprime exito'):
            assert frag in v, frag


# ============================================================================ 2. RESTORE

@pytest.fixture
def entorno_restore(tmp_path):
    """Un `psql` FALSO en el PATH que registra sus argumentos y sale con el código de FAKE_PSQL_RC."""
    fake = tmp_path / 'bin'
    fake.mkdir()
    psql = fake / 'psql'
    psql.write_text('#!/usr/bin/env bash\ncat > /dev/null\necho "$@" > "$FAKE_PSQL_ARGS"\nexit "${FAKE_PSQL_RC:-0}"\n', encoding='utf-8', newline='\n')
    psql.chmod(psql.stat().st_mode | stat.S_IEXEC)
    args = tmp_path / 'psql_args.txt'

    def ejecutar(dump: Path, rc: int = 0):
        env = {**os.environ, 'PATH': f'{fake}{os.pathsep}{os.environ["PATH"]}', 'FAKE_PSQL_ARGS': args.as_posix(), 'FAKE_PSQL_RC': str(rc),
               'DB_CONTAINER': 'no-existe-este-contenedor'}
        # rutas con barras normales: en Windows, Git Bash se come las barras invertidas de `C:\Users\...`
        r = subprocess.run([_bash(), 'scripts/ops/restore_db.sh', Path(dump).as_posix(), '--yes'], env=env, capture_output=True,
                           text=True, encoding='utf-8', errors='replace', timeout=60, cwd=ROOT)
        return r, (args.read_text(encoding='utf-8') if args.exists() else None)
    return ejecutar


def _dump(path: Path, contenido='-- PostgreSQL database dump\nSELECT 1;\n'):
    with gzip.open(path, 'wt', encoding='utf-8') as f:
        f.write(contenido)
    return path


class TestRestoreScript:
    def test_restauracion_correcta_usa_on_error_stop_y_una_sola_transaccion(self, entorno_restore, tmp_path):
        r, args = entorno_restore(_dump(tmp_path / 'ok.sql.gz'))
        assert r.returncode == 0 and 'finalizada con éxito' in r.stdout
        assert 'ON_ERROR_STOP=1' in args and '--single-transaction' in args

    def test_un_error_de_psql_devuelve_error_y_no_dice_exito(self, entorno_restore, tmp_path):
        """El bug original: psql sin ON_ERROR_STOP salía con 0 aunque fallara una sentencia y el script imprimía 'éxito'."""
        r, _ = entorno_restore(_dump(tmp_path / 'ok.sql.gz'), rc=3)
        assert r.returncode != 0 and 'finalizada con éxito' not in r.stdout

    def test_un_volcado_real_grande_se_acepta(self, entorno_restore, tmp_path):
        """Regresión (la destapó verify_docker.sh): con pipefail, `gzip | head | grep` daba SIGPIPE en volcados de más de 4 KB y el restore
        rechazaba respaldos LEGÍTIMOS. Los volcados de prueba eran pequeños y no lo veían."""
        grande = '-- PostgreSQL database dump\n' + ''.join(f"INSERT INTO t VALUES ({n}, '{'x' * 60}');\n" for n in range(5000))
        assert len(grande) > 100_000
        r, args = entorno_restore(_dump(tmp_path / 'grande.sql.gz', grande))
        assert r.returncode == 0 and 'finalizada con éxito' in r.stdout and args is not None

    def test_un_gzip_truncado_se_rechaza_sin_llamar_a_psql(self, entorno_restore, tmp_path):
        buen = _dump(tmp_path / 'ok.sql.gz')
        malo = tmp_path / 'truncado.sql.gz'
        malo.write_bytes(buen.read_bytes()[:20])
        r, args = entorno_restore(malo)
        assert r.returncode != 0 and 'no es un gzip' in r.stdout and args is None

    def test_algo_que_no_es_un_volcado_de_pg_dump_se_rechaza(self, entorno_restore, tmp_path):
        r, args = entorno_restore(_dump(tmp_path / 'otro.sql.gz', 'hola mundo\n'))
        assert r.returncode != 0 and 'no parece un volcado' in r.stdout and args is None

    def test_el_archivo_inexistente_se_rechaza(self, entorno_restore, tmp_path):
        r, args = entorno_restore(tmp_path / 'no_existe.sql.gz')
        assert r.returncode != 0 and args is None

    def test_las_banderas_estan_en_el_script_y_ambos_caminos_las_usan(self):
        s = (ROOT / 'scripts' / 'ops' / 'restore_db.sh').read_text(encoding='utf-8')
        assert 'PSQL_FLAGS=(-X -v ON_ERROR_STOP=1 --single-transaction)' in s
        assert s.count('"${PSQL_FLAGS[@]}"') == 2                                  # contenedor Docker y psql directo
        assert 'docker compose stop app feeds' in s                                # y avisa de parar los servicios


# ============================================================================ 4. DOCUMENTACIÓN DE LA CLAVE PERDIDA

class TestRunbooks:
    def test_runbook_de_la_cadena_cubre_clave_perdida_y_rotacion(self):
        r = (ROOT / 'docs' / 'runbooks' / 'RUNBOOK-AUDIT-CHAIN.md').read_text(encoding='utf-8')
        for frag in ('AUDIT_CHAIN_LOST_KEY_IDS', 'AUDIT_CHAIN_PREVIOUS_KEYS', 'flask audit verify', 'Si se PIERDE la clave', 'APP_DB_USER'):
            assert frag in r, frag

    def test_runbook_de_restore_manda_parar_los_servicios_y_verificar_la_cadena(self):
        r = (ROOT / 'docs' / 'runbooks' / 'RUNBOOK-BACKUP-RESTORE.md').read_text(encoding='utf-8')
        assert 'docker compose stop app feeds' in r and 'flask audit verify' in r and 'single-transaction' in r
