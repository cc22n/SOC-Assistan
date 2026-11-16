"""
Regresión de los operativos de la Fase 0 (full-audit-report.md, verificados abiertos el 2026-11-13):
  CRIT-10  errors/413.html no existía -> TemplateNotFound -> 500
  CRIT-08  métricas por path crecían sin límite (fuga de memoria)
  CRIT-09  docker-compose sin rotación de logs
  CRIT-07  Gunicorn sync (3 workers = 3 peticiones simultáneas)
  ALTO     /health sin rollback tras fallo de BD
"""
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def clean_metrics():
    from app.utils import metrics
    metrics._endpoint_metrics.clear()
    yield metrics
    metrics._endpoint_metrics.clear()


class TestPlantilla413:
    def test_archivo_existe(self):
        assert (ROOT / 'app' / 'templates' / 'errors' / '413.html').is_file()

    def test_413_html_renderiza_sin_caer_en_500(self, app, client):
        old = app.config.get('MAX_CONTENT_LENGTH')
        app.config['MAX_CONTENT_LENGTH'] = 10
        try:
            r = client.post('/auth/login', data={'username': 'x' * 200, 'password': 'y' * 200},
                            headers={'Accept': 'text/html'})
        finally:
            app.config['MAX_CONTENT_LENGTH'] = old
        assert r.status_code == 413
        assert b'413' in r.data and 'demasiado grande'.encode() in r.data

    def test_413_json(self, app, client):
        old = app.config.get('MAX_CONTENT_LENGTH')
        app.config['MAX_CONTENT_LENGTH'] = 10
        try:
            r = client.post('/api/v2/analyze/enhanced', json={'ioc': '1.1.1.1', 'pad': 'x' * 500})
        finally:
            app.config['MAX_CONTENT_LENGTH'] = old
        assert r.status_code == 413
        assert r.get_json()['error'] == 'Request Too Large'


class TestMetricasAcotadas:
    def test_rutas_404_distintas_comparten_una_serie(self, app, client, clean_metrics):
        for i in range(25):
            client.get(f'/ruta-que-no-existe-{i}')
        assert 'unmatched' in clean_metrics._endpoint_metrics
        assert not any('ruta-que-no-existe' in k for k in clean_metrics._endpoint_metrics)
        assert len(clean_metrics._endpoint_metrics) <= 3

    def test_ids_distintos_comparten_el_mismo_endpoint(self, app, analyst_client, clean_metrics):
        for i in (1, 2, 3, 4, 5):
            analyst_client.get(f'/api/v2/incidents/{i}')
        keys = [k for k in clean_metrics._endpoint_metrics if 'incidents' in k]
        assert keys == ['incidents_api.get_incident']          # una sola serie, no una por id

    def test_tope_de_series_distintas(self, clean_metrics):
        for i in range(clean_metrics.MAX_ENDPOINT_SERIES + 200):
            clean_metrics.record_request_time(f'clave-{i}', 1.0)
        assert len(clean_metrics._endpoint_metrics) <= clean_metrics.MAX_ENDPOINT_SERIES + 1
        assert clean_metrics.OVERFLOW_ENDPOINT_KEY in clean_metrics._endpoint_metrics

    def test_claves_existentes_siguen_registrandose_tras_el_tope(self, clean_metrics):
        clean_metrics.record_request_time('conocida', 5.0)
        for i in range(clean_metrics.MAX_ENDPOINT_SERIES + 10):
            clean_metrics.record_request_time(f'otra-{i}', 1.0)
        clean_metrics.record_request_time('conocida', 7.0)
        assert clean_metrics._endpoint_metrics['conocida']._total == 2


class TestHealthRollback:
    def test_fallo_de_bd_hace_rollback_y_responde_503(self, app, client):
        from app import db
        with patch.object(db.session, 'execute', side_effect=Exception('db caida')), \
             patch.object(db.session, 'rollback') as rb:
            r = client.get('/api/v2/health')
        assert r.status_code == 503
        rb.assert_called()


class TestInfraComoCodigo:
    def test_compose_rota_logs_en_todos_los_servicios(self):
        compose = yaml.safe_load((ROOT / 'docker-compose.yml').read_text(encoding='utf-8'))
        for name, svc in compose['services'].items():
            log = svc.get('logging')
            assert log, f'{name} sin logging'
            assert log['driver'] == 'json-file'
            assert log['options']['max-size'] and log['options']['max-file'], name

    def test_gunicorn_no_es_sync(self):
        df = (ROOT / 'Dockerfile').read_text(encoding='utf-8')
        assert '--worker-class gthread' in df and '--threads' in df

    def test_healthcheck_usa_ipv4_explicito(self):
        df = (ROOT / 'Dockerfile').read_text(encoding='utf-8')
        assert '127.0.0.1:5000/api/v2/health' in df and 'localhost:5000' not in df


class TestArranqueDelContenedor:
    """
    Hallazgos de `docker compose up --build` real (2026-11-14): el contenedor entraba en bucle de
    reinicios con ModuleNotFoundError porque `python docker/init_db.py` pone /app/docker (no /app) en
    sys.path. Este bug estuvo presente desde que existe init_db.py sin que ningun test lo viera.
    """

    def test_dockerfile_define_pythonpath(self):
        df = (ROOT / 'Dockerfile').read_text(encoding='utf-8')
        assert 'PYTHONPATH=/app' in df

    def test_el_cmd_ejecuta_init_db_como_script(self):
        """Si alguien cambia a `python -m docker.init_db` o mueve el script, este test avisa de que
        PYTHONPATH deja de ser necesario (o de que hay que revisar la causa)."""
        df = (ROOT / 'Dockerfile').read_text(encoding='utf-8')
        assert 'python docker/init_db.py' in df

    def test_init_db_importa_app_por_nombre(self):
        src = (ROOT / 'docker' / 'init_db.py').read_text(encoding='utf-8')
        assert 'from app import create_app, db' in src

    def test_init_db_no_se_puede_importar_sin_pythonpath_desde_su_directorio(self):
        """Reproduce el fallo original: con sys.path[0]=docker/ y sin PYTHONPATH, `import app` falla."""
        import subprocess, sys, os
        env = {k: v for k, v in os.environ.items() if k != 'PYTHONPATH'}
        r = subprocess.run([sys.executable, '-I', '-c', 'import sys; sys.path[:] = [sys.argv[1]]; import app',
                            str(ROOT / 'docker')], capture_output=True, text=True, env=env, cwd=str(ROOT / 'docker'))
        assert r.returncode != 0 and 'No module named' in r.stderr

    def test_el_script_de_verificacion_existe_y_tiene_sintaxis_valida(self):
        import shutil, subprocess
        script = ROOT / 'scripts' / 'ops' / 'verify_docker.sh'
        assert script.is_file()
        bash = shutil.which('bash')
        if not bash:
            pytest.skip('bash no disponible')
        # Ruta RELATIVA + cwd: el bash.exe de WSL (C:\Windows\System32) no entiende rutas de Windows.
        r = subprocess.run([bash, '-n', 'scripts/ops/verify_docker.sh'], capture_output=True, text=True,
                           cwd=str(ROOT))
        if r.returncode != 0 and 'system32' in bash.lower():
            pytest.skip('el bash de PATH es el lanzador de WSL, que no puede leer el script desde Windows; '
                        'usa Git Bash para ejecutar esta comprobación')
        assert r.returncode == 0, r.stderr

    def test_los_scripts_de_shell_no_tienen_crlf(self):
        for sh in (ROOT / 'scripts' / 'ops').glob('*.sh'):
            assert b'\r\n' not in sh.read_bytes(), f'{sh.name} tiene CRLF'

    def test_gitattributes_fuerza_lf_en_scripts_y_dockerfile(self):
        ga = (ROOT / '.gitattributes').read_text(encoding='utf-8')
        assert '*.sh' in ga and 'eol=lf' in ga and 'Dockerfile' in ga
