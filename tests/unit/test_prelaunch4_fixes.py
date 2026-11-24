"""
Correcciones del informe de pre-lanzamiento 4 (verificadas con ejecución antes de actuar):

  A1  el HEALTHCHECK del contenedor (127.0.0.1) recibía 400 con ALLOWED_HOSTS=un dominio real: app unhealthy y feeds sin arrancar.
  A2  las claves de API en la query salían en el TEXTO de las excepciones (log, BD, respuesta JSON, prompt de un LLM).
  A3  Sentry: faltaban las transacciones, las variables locales y los nombres de cabecera de OTX/abuse.ch.
  A4  restore_db.sh aceptaba un dump cortado a mitad y decía "éxito"; backup_db.sh dejaba respaldos parciales con nombre válido.
  A5  restaurar en un VPS/volumen NUEVO fallaba: el dump traía GRANT a un rol (soc_app) que aún no existe.
  M1  MIGRATION_DATABASE_URL (el administrador) estaba en el entorno del proceso web.
  M3  Redis sin contraseña (la caché usa pickle).
  M6  `docker stop` mataba al daemon con SIGKILL (137); sin start-period una migración larga dejaba app unhealthy.
(M2, el tope de las claves declaradas perdidas, está en test_audit_chain.py.)
"""
import gzip
import logging
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import requests
import yaml

from app.utils import http_client, secret_redaction as sr, sentry_scrub

ROOT = Path(__file__).resolve().parents[2]
SECRETO = 'SHODANSECRET123456'


def _bash():
    import shutil
    if sys.platform == 'win32':
        for p in ('C:/Program Files/Git/bin/bash.exe', 'C:/Program Files (x86)/Git/bin/bash.exe'):
            if Path(p).exists():
                return p
        pytest.skip('no hay Git Bash: en Windows el `bash` del PATH suele ser el de WSL')
    return shutil.which('bash') or pytest.skip('no hay bash')


@pytest.fixture
def secretos(monkeypatch):
    """Una clave de API configurada en el entorno (como las de .env) y la caché de secretos limpia."""
    monkeypatch.setenv('SHODAN_API_KEY', SECRETO)
    sr.reset_cache()
    yield
    sr.reset_cache()


# ============================================================================ A1. SONDA LOCAL DE SALUD

class TestSondaLocalDeSalud:
    @pytest.fixture(autouse=True)
    def dominio_real(self, app):
        antes = app.config.get('ALLOWED_HOSTS')
        app.config['ALLOWED_HOSTS'] = ['soc.example.com']                       # como en producción: sin 127.0.0.1
        yield
        app.config['ALLOWED_HOSTS'] = antes

    def _get(self, client, host, peer, **extra):
        return client.get('/api/v2/health', base_url=f'http://{host}', environ_overrides={'REMOTE_ADDR': peer, **extra}).status_code

    def test_el_healthcheck_del_contenedor_pasa(self, client):
        """El del Dockerfile: Host 127.0.0.1:5000 desde 127.0.0.1. Antes: 400 -> unhealthy -> feeds nunca arranca."""
        assert self._get(client, '127.0.0.1:5000', '127.0.0.1') != 400
        assert self._get(client, '[::1]:5000', '::1') != 400

    def test_control_el_dominio_real_sigue_funcionando(self, client):
        assert self._get(client, 'soc.example.com', '203.0.113.7') != 400

    @pytest.mark.parametrize('host,peer', [('127.0.0.1:5000', '172.18.0.1'), ('127.0.0.1', '203.0.113.7'), ('localhost', '10.0.0.5')])
    def test_loopback_en_el_host_pero_cliente_externo_se_rechaza(self, client, host, peer):
        """Lo que llega por el proxy viene de la IP de la red de Docker, nunca de 127.0.0.1."""
        assert self._get(client, host, peer) == 400

    def test_un_x_forwarded_for_falsificado_no_se_hace_pasar_por_loopback(self, client):
        """ProxyFix reescribe REMOTE_ADDR con el X-Forwarded-For del cliente; el cliente TCP real queda en `werkzeug.proxy_fix.orig`."""
        assert self._get(client, '127.0.0.1:5000', '127.0.0.1', **{'werkzeug.proxy_fix.orig': {'REMOTE_ADDR': '203.0.113.9'}}) == 400

    @pytest.mark.parametrize('ruta', ['/auth/login', '/dashboard', '/api/v2/health/extra', '/api/v2/healthz', '/static/ui-actions.js', '/'])
    def test_la_excepcion_es_solo_para_la_ruta_del_healthcheck(self, client, ruta):
        """Un Host de loopback desde un cliente local (p. ej. un nginx en el mismo host reenviando un Host falso) NO se acepta en otras rutas."""
        assert client.get(ruta, base_url='http://127.0.0.1:5000', environ_overrides={'REMOTE_ADDR': '127.0.0.1'}).status_code == 400
        assert client.get(ruta, base_url='http://localhost', environ_overrides={'REMOTE_ADDR': '127.0.0.1'}).status_code == 400

    @pytest.mark.parametrize('host', ['evil.com', 'soc.example.com.evil.com', '169.254.169.254', '10.0.0.5'])
    def test_otros_hosts_siguen_rechazados_aunque_el_cliente_sea_local(self, client, host):
        assert self._get(client, host, '127.0.0.1') == 400


# ============================================================================ A2. SECRETOS EN EL TEXTO DE LAS EXCEPCIONES

class TestRedaccionDeSecretos:
    def test_el_valor_configurado_se_redacta_donde_sea(self, secretos):
        assert SECRETO not in sr.redact_secrets(f'cualquier cosa {SECRETO} mas cosas')

    @pytest.mark.parametrize('texto', [
        f'/shodan/host/8.8.8.8?key={SECRETO}', f'https://x/v1?apiKey={SECRETO}&ip=1.1.1.1', f'?token={SECRETO}', f'?access_token={SECRETO}',
        f'Authorization: Bearer {SECRETO}', f'postgresql://soc_app:{SECRETO}@db:5432/x',
    ])
    def test_los_patrones_cubren_claves_aunque_no_esten_configuradas(self, texto):
        sr.reset_cache()
        assert SECRETO not in sr.redact_secrets(texto)

    def test_lo_demas_se_conserva(self):
        out = sr.redact_secrets(f'GET /v1?ip=1.2.3.4&key={SECRETO}&otro=ok falló: timeout')
        assert 'ip=1.2.3.4' in out and 'otro=ok' in out and 'falló: timeout' in out

    def test_valores_cortos_o_no_secretos_no_se_tocan(self, monkeypatch):
        monkeypatch.setenv('X_API_KEY', 'corta')                 # < 8 caracteres: no se trata como secreto (evita redactar palabras comunes)
        monkeypatch.setenv('LOG_LEVEL', 'INFO_INFO_INFO')        # el nombre no es de secreto
        sr.reset_cache()
        assert sr.redact_secrets('corta INFO_INFO_INFO') == 'corta INFO_INFO_INFO'

    def test_listas_separadas_por_comas(self, monkeypatch):
        monkeypatch.setenv('AUDIT_CHAIN_PREVIOUS_KEYS', 'k' * 32 + ',' + 'j' * 32)
        sr.reset_cache()
        assert 'k' * 32 not in sr.redact_secrets('x ' + 'k' * 32) and 'j' * 32 not in sr.redact_secrets('y ' + 'j' * 32)

    def test_http_get_no_deja_salir_la_clave_en_la_excepcion_de_red_real(self, secretos):
        """Fallo de red REAL (puerto cerrado): el texto de la excepción de requests lleva la URL con la clave."""
        url = f'http://127.0.0.1:1/shodan/host/8.8.8.8?key={SECRETO}'
        with pytest.raises(requests.exceptions.RequestException) as crudo:
            requests.get(url, timeout=3)
        assert SECRETO in str(crudo.value)                                       # CONTROL: sin el arreglo, la clave salía
        with pytest.raises(requests.exceptions.ConnectionError) as limpia:       # y el TIPO se conserva (los `except ConnectionError` valen)
            http_client.http_get(url, timeout=3)
        assert SECRETO not in str(limpia.value) and SECRETO not in repr(limpia.value)
        assert limpia.value.__cause__ is None and limpia.value.__suppress_context__          # `from None`: el traceback tampoco la arrastra

    def test_http_post_igual(self, secretos):
        with pytest.raises(requests.exceptions.ConnectionError) as e:
            http_client.http_post(f'http://127.0.0.1:1/x?token={SECRETO}', json={}, timeout=3)
        assert SECRETO not in str(e.value)

    def test_el_traceback_formateado_tampoco_la_lleva(self, secretos):
        import traceback
        try:
            http_client.http_get(f'http://127.0.0.1:1/x?key={SECRETO}', timeout=3)
        except requests.RequestException as e:
            assert SECRETO not in ''.join(traceback.format_exception(type(e), e, e.__traceback__))

    def test_una_excepcion_sin_secretos_se_relanza_intacta(self, monkeypatch):
        original = requests.exceptions.Timeout('timeout sin nada raro')
        monkeypatch.setattr(requests, 'get', lambda *a, **k: (_ for _ in ()).throw(original))
        with pytest.raises(requests.exceptions.Timeout) as e:
            http_client.http_get('http://example.test/x')
        assert e.value is original

    def test_se_conserva_response_y_el_tipo_en_http_error(self, secretos):
        resp = requests.Response()
        resp.status_code = 503
        err = requests.exceptions.HTTPError(f'503 for url: https://x/y?key={SECRETO}', response=resp)
        nueva = http_client._sanitized(err)
        assert SECRETO not in str(nueva) and isinstance(nueva, requests.exceptions.HTTPError) and nueva.response is resp

    # (clase, clave en config['API_KEYS'], atributo de la clave, atributo de la URL base, método, argumento): los 5 con la clave EN LA QUERY
    CLIENTES = [
        ('ShodanClient', 'shodan', 'api_key', 'base_url', 'check_ip', '8.8.8.8'),
        ('PulsediveClient', 'pulsedive', 'api_key', 'base_url', 'get_indicator', '8.8.8.8'),
        ('GoogleSafeBrowsingClient', 'google_safebrowsing', 'api_key', 'base_url', 'check_url', 'http://ejemplo.test/x'),
        ('IPinfoClient', 'ipinfo', 'token', 'base_url', 'check_ip', '8.8.8.8'),
        ('IPGeolocationClient', 'ipgeolocation', 'api_key', 'base_url', 'check_ip', '8.8.8.8'),
    ]

    @pytest.mark.parametrize('cliente,nombre,attr_clave,attr_url,metodo,arg', CLIENTES, ids=[c[0] for c in CLIENTES])
    def test_un_cliente_real_devuelve_el_error_sin_la_clave(self, app, secretos, cliente, nombre, attr_clave, attr_url, metodo, arg):
        """De punta a punta con CADA cliente que lleva la clave en la query y con un fallo de red real: lo que devuelve (y acaba en la
        columna `*_data` de la BD, en la UI, en exports y en el prompt de un LLM) no lleva la clave."""
        import app.services.new_api_clients as nac
        app.config.setdefault('API_KEYS', {})
        app.config['API_KEYS'][nombre] = SECRETO
        c = getattr(nac, cliente)()
        assert getattr(c, attr_clave) == SECRETO                                 # CONTROL: el cliente SÍ usa esta clave
        setattr(c, attr_url, 'http://127.0.0.1:1' + ('/x' if cliente == 'GoogleSafeBrowsingClient' else ''))
        out = getattr(c, metodo)(arg)
        assert 'error' in out and SECRETO not in str(out), out

    def test_control_sin_http_client_la_clave_si_salia(self, app, secretos, monkeypatch):
        """El detector no es vacuo: si el cliente llamara a requests directamente, el resultado SÍ llevaría la clave."""
        import app.services.new_api_clients as nac
        app.config.setdefault('API_KEYS', {})['shodan'] = SECRETO
        monkeypatch.setattr(nac, 'http_get', lambda url, **kw: requests.get(url, **kw))
        c = nac.ShodanClient()
        c.base_url = 'http://127.0.0.1:1'
        assert SECRETO in str(c.check_ip('8.8.8.8'))

    def test_ningun_cliente_importa_requests_para_llamar_directamente(self):
        """El punto único (http_client) solo sirve si NADIE lo esquiva: una llamada directa a requests.* volvería a filtrar la clave."""
        directas = []
        for f in (ROOT / 'app').rglob('*.py'):
            if f.name == 'http_client.py':
                continue
            for n, linea in enumerate(f.read_text(encoding='utf-8').splitlines(), 1):
                if re.search(r'\brequests\.(get|post|put|delete|request|head|patch)\(', linea) and not linea.strip().startswith('#'):
                    directas.append(f'{f.relative_to(ROOT)}:{n}')
        assert directas == [], directas


class TestFiltroDeLogs:
    def _handler(self):
        import io
        buf = io.StringIO()
        h = logging.StreamHandler(buf)
        h.setFormatter(logging.Formatter('%(message)s'))
        sr.install_log_redaction([h])
        lg = logging.getLogger('prueba.secretos')
        lg.propagate = False
        lg.handlers[:] = [h]
        lg.setLevel(logging.DEBUG)
        return lg, buf

    def test_mensaje_y_argumentos(self, secretos):
        lg, buf = self._handler()
        lg.error('fallo %s', f'Max retries exceeded with url: /x?key={SECRETO}')
        lg.error(f'directo {SECRETO}')
        assert SECRETO not in buf.getvalue() and 'Max retries exceeded' in buf.getvalue()

    def test_traza_de_excepcion(self, secretos):
        lg, buf = self._handler()
        try:
            raise requests.exceptions.ConnectionError(f'url: /x?key={SECRETO}')
        except Exception:
            lg.exception('falló')
        out = buf.getvalue()
        assert SECRETO not in out and 'ConnectionError' in out and 'Traceback' in out          # la traza sigue ahí, sin la clave

    def test_control_sin_filtro_la_clave_sale(self, secretos):
        import io
        buf = io.StringIO()
        lg = logging.getLogger('prueba.sin_filtro')
        lg.propagate = False
        lg.handlers[:] = [logging.StreamHandler(buf)]
        lg.error(f'x {SECRETO}')
        assert SECRETO in buf.getvalue()

    def test_urllib3_registra_la_url_con_la_clave_al_reintentar_y_se_redacta(self, secretos):
        """urllib3 (connectionpool) escribe "Retrying ... : /ruta?key=..." en WARNING: se filtra en el propio logger."""
        sr.install_log_redaction([])
        import io
        buf = io.StringIO()
        h = logging.StreamHandler(buf)
        lg = logging.getLogger('urllib3.connectionpool')
        lg.addHandler(h)
        try:
            lg.warning("Retrying (Retry(total=1)) after connection broken by 'X': /shodan/host/8.8.8.8?key=%s", SECRETO)
        finally:
            lg.removeHandler(h)
        assert SECRETO not in buf.getvalue() and 'Retrying' in buf.getvalue()

    def test_la_app_instala_el_filtro_en_sus_handlers(self, app):
        from app import setup_logging
        setup_logging(app)
        handlers = list(app.logger.handlers) + list(logging.getLogger().handlers)
        assert any(isinstance(f, sr.SecretRedactingFilter) for h in app.logger.handlers for f in h.filters) or not app.logger.handlers
        assert any(isinstance(f, sr.SecretRedactingFilter) for f in logging.getLogger('urllib3.connectionpool').filters)

    def test_el_formateador_json_conserva_la_traza_redactada(self, secretos):
        import json
        from app import JSONFormatter
        lg, _ = self._handler()
        rec = logging.LogRecord('x', logging.ERROR, __file__, 1, 'fallo', (), None)
        try:
            raise ValueError(f'clave {SECRETO}')
        except ValueError:
            import sys as _s
            rec.exc_info = _s.exc_info()
        sr.SecretRedactingFilter().filter(rec)
        salida = JSONFormatter().format(rec)
        assert SECRETO not in salida and 'ValueError' in json.loads(salida)['exception']


# ============================================================================ A3. SENTRY

class TestSentryCompleto:
    def test_incluye_transacciones_y_no_manda_variables_locales(self):
        kw = sentry_scrub.sentry_init_kwargs('https://k@o0.ingest.sentry.io/1')
        assert kw['before_send_transaction'] is sentry_scrub.before_send
        assert kw['include_local_variables'] is False and kw['max_breadcrumbs'] <= 50

    @pytest.mark.parametrize('cabecera', ['X-OTX-API-KEY', 'Auth-Key', 'X-ApiKey', 'Key', 'api_key', 'x-api-key', 'Authorization', 'Cookie',
                                          'auth_key', 'vt_api_key', 'access_token', 'client_secret', 'password', 'TOKEN'])
    def test_cabeceras_y_variables_de_las_apis_reales(self, cabecera):
        """abuse.ch usa `Auth-Key` y OTX `X-OTX-API-KEY`: no coincidían por igualdad con la lista corta de la primera versión."""
        out = sentry_scrub.scrub({'headers': {cabecera: 'VALORSECRETO99'}, cabecera: 'OTROSECRETO'})
        assert 'VALORSECRETO99' not in str(out) and 'OTROSECRETO' not in str(out)

    def test_nombres_normales_no_se_redactan(self):
        out = sentry_scrub.scrub({'headers': {'Accept': 'json', 'User-Agent': 'x', 'Content-Type': 'a'}, 'ioc': '8.8.8.8', 'monkeys': 'ok'})
        assert out['headers']['Accept'] == 'json' and out['ioc'] == '8.8.8.8' and out['monkeys'] == 'ok'

    def test_una_transaccion_con_spans_se_limpia(self, secretos):
        """Lo que NO cubría la primera versión: el 5 % de los análisis enviaba las claves en los spans de las peticiones salientes."""
        tx = {'type': 'transaction', 'spans': [{'op': 'http.client', 'description': f'GET https://x/shodan/host/8.8.8.8?key={SECRETO}',
                                               'data': {'url': f'https://x/y?apiKey={SECRETO}', 'http.query': f'key={SECRETO}'}}],
              'request': {'headers': {'X-OTX-API-KEY': SECRETO}}}
        assert SECRETO not in str(sentry_scrub.before_send(tx))

    def test_con_el_sdk_real_la_transaccion_sale_limpia(self, secretos):
        import sentry_sdk
        capturados = []
        kw = sentry_scrub.sentry_init_kwargs('https://k@o0.ingest.sentry.io/1')
        kw.update(traces_sample_rate=1.0, before_send_transaction=lambda e, h: capturados.append(sentry_scrub.before_send(e, h)) or None)
        try:
            sentry_sdk.init(**kw)
            with sentry_sdk.start_transaction(name='analisis'):
                with sentry_sdk.start_span(op='http.client', description=f'GET https://x/y?key={SECRETO}') as sp:
                    sp.set_data('http.query', f'key={SECRETO}')
        finally:
            sentry_sdk.init()
        if not capturados:
            pytest.skip('esta version del SDK no entrego la transaccion al hook')
        assert SECRETO not in str(capturados)


# ============================================================================ A4 / A5. BACKUP Y RESTORE

@pytest.fixture
def entorno_scripts(tmp_path):
    """`psql` y `pg_dump` FALSOS en el PATH. pg_dump emite lo que diga FAKE_DUMP (y sale con FAKE_DUMP_RC); psql guarda argumentos y stdin."""
    fake = tmp_path / 'bin'
    fake.mkdir()
    (fake / 'psql').write_text('#!/usr/bin/env bash\ncat > "$FAKE_PSQL_STDIN"\necho "$@" > "$FAKE_PSQL_ARGS"\nexit "${FAKE_PSQL_RC:-0}"\n',
                               encoding='utf-8', newline='\n')
    (fake / 'pg_dump').write_text('#!/usr/bin/env bash\necho "$@" > "$FAKE_PGDUMP_ARGS"\nprintf "%s" "$FAKE_DUMP"\nexit "${FAKE_DUMP_RC:-0}"\n',
                                  encoding='utf-8', newline='\n')
    for n in ('psql', 'pg_dump'):
        (fake / n).chmod((fake / n).stat().st_mode | stat.S_IEXEC)

    def base_env(**extra):
        return {**os.environ, 'PATH': f'{fake}{os.pathsep}{os.environ["PATH"]}', 'DB_CONTAINER': 'no-existe-este-contenedor',
                'FAKE_PSQL_ARGS': (tmp_path / 'psql_args').as_posix(), 'FAKE_PSQL_STDIN': (tmp_path / 'psql_stdin.sql').as_posix(),
                'FAKE_PGDUMP_ARGS': (tmp_path / 'pgdump_args').as_posix(), **extra}

    def correr(script, *args, **extra):
        return subprocess.run([_bash(), f'scripts/ops/{script}', *args], env=base_env(**extra), capture_output=True, text=True,
                              encoding='utf-8', errors='replace', timeout=60, cwd=ROOT)
    correr.tmp = tmp_path
    return correr


COMPLETO = '-- PostgreSQL database dump\nCREATE TABLE t (x int);\n-- PostgreSQL database dump complete\n'


class TestBackup:
    def test_dump_completo_se_guarda_con_nombre_definitivo_y_sin_parciales(self, entorno_scripts):
        d = entorno_scripts.tmp / 'bk'
        r = entorno_scripts('backup_db.sh', BACKUP_DIR=d.as_posix(), FAKE_DUMP=COMPLETO)
        assert r.returncode == 0, r.stdout + r.stderr
        archivos = sorted(p.name for p in d.iterdir())
        assert len(archivos) == 1 and archivos[0].endswith('.sql.gz') and not archivos[0].endswith('.partial')
        assert 'PostgreSQL database dump complete' in gzip.open(d / archivos[0], 'rt', encoding='utf-8').read()

    def test_un_dump_incompleto_no_queda_con_nombre_valido(self, entorno_scripts):
        """EL BUG (A4): un volcado cortado a mitad pasaba `gzip -t` y quedaba como respaldo válido."""
        d = entorno_scripts.tmp / 'bk'
        r = entorno_scripts('backup_db.sh', BACKUP_DIR=d.as_posix(), FAKE_DUMP='-- PostgreSQL database dump\nCREATE TABLE t (x int);\n')
        assert r.returncode != 0 and 'INCOMPLETO' in r.stdout
        assert list(d.iterdir()) == []                                   # ni .sql.gz ni .partial

    def test_si_pg_dump_falla_a_mitad_no_queda_nada(self, entorno_scripts):
        d = entorno_scripts.tmp / 'bk'
        r = entorno_scripts('backup_db.sh', BACKUP_DIR=d.as_posix(), FAKE_DUMP='-- PostgreSQL database dump\nparcial', FAKE_DUMP_RC='3')
        assert r.returncode != 0 and list(d.iterdir()) == []

    def test_pg_dump_se_invoca_sin_privilegios_y_con_clean(self, entorno_scripts):
        d = entorno_scripts.tmp / 'bk'
        entorno_scripts('backup_db.sh', BACKUP_DIR=d.as_posix(), FAKE_DUMP=COMPLETO)
        args = (entorno_scripts.tmp / 'pgdump_args').read_text(encoding='utf-8')
        assert '--no-acl' in args and '--clean' in args and '--if-exists' in args

    @pytest.mark.skipif(sys.platform == 'win32', reason='los permisos POSIX no se aplican en Windows')
    def test_permisos_restrictivos(self, entorno_scripts):
        d = entorno_scripts.tmp / 'bk'
        entorno_scripts('backup_db.sh', BACKUP_DIR=d.as_posix(), FAKE_DUMP=COMPLETO)
        f = next(d.iterdir())
        assert stat.S_IMODE(f.stat().st_mode) == 0o600 and stat.S_IMODE(d.stat().st_mode) == 0o700

    def test_la_rotacion_solo_toca_respaldos_completos(self):
        s = (ROOT / 'scripts' / 'ops' / 'backup_db.sh').read_text(encoding='utf-8')
        assert 'soc_agent_*.sql.gz' in s and '.partial' in s


class TestRestoreIncompletoYPrivilegios:
    def _dump(self, tmp, contenido, nombre='r.sql.gz'):
        p = tmp / nombre
        with gzip.open(p, 'wt', encoding='utf-8') as f:
            f.write(contenido)
        return p.as_posix()

    def test_un_dump_cortado_con_cabecera_y_gzip_validos_se_rechaza(self, entorno_scripts):
        """EL BUG (A4): restauró, dijo 'éxito' y dejó la BD sin triggers ni claves."""
        p = self._dump(entorno_scripts.tmp, '-- PostgreSQL database dump\nCREATE TABLE t (x int);\n' + 'INSERT INTO t VALUES (1);\n' * 2000)
        r = entorno_scripts('restore_db.sh', p, '--yes')
        assert r.returncode != 0 and 'INCOMPLETO' in r.stdout and 'finalizada con' not in r.stdout
        assert not (entorno_scripts.tmp / 'psql_args').exists()                   # no se tocó la BD

    def test_un_dump_completo_se_restaura(self, entorno_scripts):
        r = entorno_scripts('restore_db.sh', self._dump(entorno_scripts.tmp, COMPLETO), '--yes')
        assert r.returncode == 0 and 'finalizada con' in r.stdout

    def test_los_grant_de_respaldos_antiguos_no_llegan_a_psql(self, entorno_scripts):
        """A5: en un VPS nuevo el rol soc_app no existe y `GRANT ... TO soc_app` aborta todo el restore (exit 3, BD vacía)."""
        sql = ('-- PostgreSQL database dump\nCREATE TABLE t (x int);\nGRANT SELECT ON TABLE t TO soc_app;\nREVOKE ALL ON TABLE t FROM PUBLIC;\n'
               'ALTER DEFAULT PRIVILEGES FOR ROLE soc_admin IN SCHEMA public GRANT ALL ON TABLES TO soc_app;\nSELECT 1;\n'
               '-- PostgreSQL database dump complete\n')
        r = entorno_scripts('restore_db.sh', self._dump(entorno_scripts.tmp, sql), '--yes')
        recibido = (entorno_scripts.tmp / 'psql_stdin.sql').read_text(encoding='utf-8')
        assert r.returncode == 0 and 'CREATE TABLE t' in recibido and 'SELECT 1;' in recibido
        assert 'GRANT SELECT' not in recibido and 'REVOKE ALL' not in recibido and 'ALTER DEFAULT PRIVILEGES' not in recibido

    def test_una_fila_de_datos_que_empieza_por_grant_NO_se_toca(self, entorno_scripts):
        """El filtro solo actúa FUERA de los bloques COPY: borrar una fila de datos sería corromper el restore en silencio."""
        sql = ('-- PostgreSQL database dump\nCOPY public.t (x) FROM stdin;\nGRANT me everything\nREVOKE nada\nALTER DEFAULT PRIVILEGES x\n\\.\n'
               'GRANT SELECT ON TABLE t TO soc_app;\n-- PostgreSQL database dump complete\n')
        r = entorno_scripts('restore_db.sh', self._dump(entorno_scripts.tmp, sql), '--yes')
        recibido = (entorno_scripts.tmp / 'psql_stdin.sql').read_text(encoding='utf-8')
        assert r.returncode == 0
        assert 'GRANT me everything' in recibido and 'REVOKE nada' in recibido and 'ALTER DEFAULT PRIVILEGES x' in recibido   # datos intactos
        assert 'GRANT SELECT ON TABLE t TO soc_app' not in recibido                                                          # el GRANT real, fuera

    def test_el_runbook_documenta_el_restore_en_un_servidor_nuevo(self):
        r = (ROOT / 'docs' / 'runbooks' / 'RUNBOOK-BACKUP-RESTORE.md').read_text(encoding='utf-8')
        for frag in ('VPS o volumen NUEVO', 'docker compose up -d db', 'cifrados', '0600', 'MIGRATION_DATABASE_URL'):
            assert frag in r, frag


# ============================================================================ M1, M3, M6. DESPLIEGUE

class TestDespliegue:
    @pytest.fixture(scope='class')
    def compose(self):
        return yaml.safe_load((ROOT / 'docker-compose.yml').read_text(encoding='utf-8'))

    @staticmethod
    def _env(svc):
        e = svc.get('environment') or []
        return {k: str(v) for k, v in e.items()} if isinstance(e, dict) else dict(x.split('=', 1) for x in e)

    def test_el_proceso_web_no_hereda_las_credenciales_del_administrador(self):
        d = (ROOT / 'Dockerfile').read_text(encoding='utf-8')
        m = re.search(r'^CMD \[.*\]$', d, re.M)
        assert m and 'init_db.py' in m.group(0)
        assert m.group(0).index('init_db.py') < m.group(0).index('env -u MIGRATION_DATABASE_URL') < m.group(0).index('gunicorn')
        assert 'exec env -u MIGRATION_DATABASE_URL gunicorn' in m.group(0)         # exec: gunicorn es el PID 1 con el entorno ya limpio

    def test_redis_exige_contrasena_y_la_app_la_usa(self, compose):
        redis = compose['services']['redis']
        assert '--requirepass' in ' '.join(redis['command']) and self._env(redis)['REDIS_PASSWORD'].startswith('${REDIS_PASSWORD:?')
        assert 'REDIS_PASSWORD' in ' '.join(redis['healthcheck']['test'])
        for n in ('app', 'feeds'):
            url = self._env(compose['services'][n])['REDIS_URL']
            assert url.startswith('redis://:${REDIS_PASSWORD:?'), n
        assert 'redis://redis' not in (ROOT / 'docker-compose.yml').read_text(encoding='utf-8')     # ninguna URL sin contraseña

    def test_parada_ordenada(self, compose):
        assert compose['services']['feeds']['init'] is True                  # el daemon no maneja SIGTERM: sin init moría con SIGKILL (137)
        assert int(str(compose['services']['app']['stop_grace_period']).rstrip('s')) > 30      # > graceful_timeout de Gunicorn
        assert 'stop_grace_period' in compose['services']['feeds']

    def test_app_no_usa_init_porque_anularia_el_env_u(self, compose):
        """Con `init: true` el PID 1 es tini y conserva el entorno ORIGINAL del contenedor (con las credenciales del administrador),
        legible desde /proc/1/environ por cualquier proceso del mismo usuario: anula `env -u MIGRATION_DATABASE_URL` (lo destapó verify_docker)."""
        assert not compose['services']['app'].get('init')
        assert 'MIGRATION_DATABASE_URL' not in self._env(compose['services']['feeds'])            # feeds sí puede llevar init: no recibe el administrador

    def test_el_healthcheck_tiene_periodo_de_arranque(self):
        assert re.search(r'^HEALTHCHECK .*--start-period=\d+s', (ROOT / 'Dockerfile').read_text(encoding='utf-8'), re.M | re.S)

    def test_las_variables_nuevas_estan_documentadas_sin_valores_reales(self):
        env = (ROOT / '.env.example').read_text(encoding='utf-8')
        assert 'REDIS_PASSWORD=' in env and not any(re.match(r'REDIS_PASSWORD=.+', l) for l in env.splitlines())

    def test_verify_docker_prueba_lo_nuevo(self):
        v = (ROOT / 'scripts' / 'ops' / 'verify_docker.sh').read_text(encoding='utf-8')
        for frag in ('REDIS_PASSWORD', 'NOAUTH', 'MIGRATION_DATABASE_URL', 'volumen NUEVO', 'ALLOWED_HOSTS'):
            assert frag in v, frag
