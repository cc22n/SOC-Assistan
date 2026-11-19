"""
ThreatFox: coincidencia EXACTA y presencia en las estrategias de IP y dominio.

ThreatFox busca por coincidencia parcial (verificado en vivo 2026-11-18): 'google.com' devuelve
'google-proxy-66-102-6-76.google.com' y URLs de malware alojado en github.com; y `exact_match=true` no sirve
para IPs porque sus IOC son 'ip:puerto'. Sin el filtro del cliente, 4 de 10 dominios benignos salían "encontrados"
y sumaban +30. Las formas de las respuestas de abajo son las reales.
"""
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.services.llm_orchestrator import LLMOrchestrator

ROOT = Path(__file__).resolve().parents[2]
SNAPS = json.loads((ROOT / 'tests/fixtures/baseline/snapshots.json').read_text(encoding='utf-8'))
DATASET = json.loads((ROOT / 'scripts/baseline/dataset.json').read_text(encoding='utf-8'))


def _entry(ioc_type, ioc, malware='ClearFake'):
    return {'ioc_type': ioc_type, 'ioc': ioc, 'threat_type': 'botnet_cc', 'threat_type_desc': 'C2',
            'malware_printable': malware, 'confidence_level': 90, 'first_seen': '2026-11-18 17:47:14 UTC', 'tags': None}


def _resp(entries):
    m = MagicMock()
    m.status_code = 200
    m.json.return_value = {'query_status': 'ok', 'data': entries}
    return m


@pytest.fixture
def app_ctx(app):
    with app.app_context():
        yield


@pytest.fixture
def client(app_ctx):
    from app.services.new_api_clients import ThreatFoxClient
    return ThreatFoxClient()


class TestCoincidenciaExacta:
    def test_dominio_benigno_no_se_marca_por_subdominios_ajenos(self, client):
        """Caso real: google.com -> 32 IOC de 'google-proxy-...google.com'."""
        data = [_entry('domain', 'google-proxy-66-102-6-76.google.com'), _entry('domain', 'rate-limited-proxy-74-125-151-97.google.com')]
        with patch('app.services.new_api_clients.http_post', return_value=_resp(data)):
            assert client.search_ioc('google.com', 'domain') == {'found': False}

    def test_dominio_benigno_no_se_marca_por_urls_alojadas_en_el(self, client):
        """Caso real: github.com -> URL de ClearFake alojada en github (el sitio no es malicioso)."""
        data = [_entry('url', 'https://github.com/someone/payload.exe')]
        with patch('app.services.new_api_clients.http_post', return_value=_resp(data)):
            assert client.search_ioc('github.com', 'domain')['found'] is False

    def test_control_dominio_exacto_si_se_marca(self, client):
        data = [_entry('domain', 'n3.asas777.org', 'Vidar')]
        with patch('app.services.new_api_clients.http_post', return_value=_resp(data)):
            r = client.search_ioc('n3.asas777.org', 'domain')
        assert r['found'] is True and r['malware'] == 'Vidar' and r['total_results'] == 1

    def test_dominio_no_distingue_mayusculas(self, client):
        with patch('app.services.new_api_clients.http_post', return_value=_resp([_entry('domain', 'Evil.Example.ORG')])):
            assert client.search_ioc('evil.example.org', 'domain')['found'] is True

    def test_ip_coincide_con_el_host_de_ip_port(self, client):
        data = [_entry('ip:port', '217.216.54.78:20300', 'AsyncRAT'), _entry('ip:port', '217.216.54.78:20200', 'AsyncRAT')]
        with patch('app.services.new_api_clients.http_post', return_value=_resp(data)):
            r = client.search_ioc('217.216.54.78', 'ip')
        assert r['found'] is True and r['total_results'] == 2

    def test_ip_no_coincide_por_prefijo(self, client):
        """Buscar 1.1.1.1 puede devolver 1.1.1.10:80 o 11.1.1.1:80 por subcadena."""
        data = [_entry('ip:port', '1.1.1.10:80'), _entry('ip:port', '11.1.1.1:8080')]
        with patch('app.services.new_api_clients.http_post', return_value=_resp(data)):
            assert client.search_ioc('1.1.1.1', 'ip') == {'found': False}

    def test_ip_no_se_confunde_con_un_dominio_de_mismo_texto(self, client):
        with patch('app.services.new_api_clients.http_post', return_value=_resp([_entry('domain', '1.2.3.4')])):
            assert client.search_ioc('1.2.3.4', 'ip')['found'] is False

    def test_url_exacta(self, client):
        u = 'http://203.0.113.9/a.sh'
        with patch('app.services.new_api_clients.http_post', return_value=_resp([_entry('url', u)])):
            assert client.search_ioc(u, 'url')['found'] is True
        with patch('app.services.new_api_clients.http_post', return_value=_resp([_entry('url', u + '/otra')])):
            assert client.search_ioc(u, 'url')['found'] is False

    @pytest.mark.parametrize('tipo_ioc', ['sha256_hash', 'md5_hash'])
    def test_hash_exacto_sin_importar_mayusculas(self, client, tipo_ioc):
        h = 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855'
        with patch('app.services.new_api_clients.http_post', return_value=_resp([_entry(tipo_ioc, h.lower())])):
            assert client.search_ioc(h, 'hash')['found'] is True

    def test_sin_tipo_exige_igualdad_textual(self, client):
        with patch('app.services.new_api_clients.http_post', return_value=_resp([_entry('domain', 'a.evil.com')])):
            assert client.search_ioc('evil.com')['found'] is False

    @pytest.mark.parametrize('payload', [
        {'query_status': 'no_result', 'data': 'Your search did not yield any results'},
        {'query_status': 'ok', 'data': None},
        {'query_status': 'ok', 'data': 'texto inesperado'},
    ])
    def test_respuestas_degeneradas_no_rompen(self, client, payload):
        m = MagicMock(status_code=200)
        m.json.return_value = payload
        with patch('app.services.new_api_clients.http_post', return_value=m):
            assert client.search_ioc('x.com', 'domain') == {'found': False}


class TestEstrategiasYDespacho:
    def test_ip_y_dominio_consultan_threatfox(self, app_ctx):
        o = LLMOrchestrator()
        assert 'threatfox' in o.strategies['ip'] and 'threatfox' in o.strategies['domain']

    def test_despacho_pasa_el_tipo_del_ioc(self):
        from app.services import async_executor
        src = Path(async_executor.__file__).read_text(encoding='utf-8')
        for tipo in ('ip', 'domain', 'hash', 'url'):
            assert f"('threatfox', '{tipo}'):" in src and f"client.search_ioc(ioc, '{tipo}')" in src


class TestContraDatosReales:
    """Guarda sobre las respuestas reales congeladas: ThreatFox no marca nada que no sea malicioso."""

    def _found(self, row):
        r = SNAPS[f"{row['type']}:{row['value']}"]['api_results'].get('threatfox')
        return None if r is None else r.get('found')

    def test_cero_falsos_positivos_en_benignos_y_ambiguos(self):
        malos = [r['value'] for r in DATASET if r['label'] != 'malicious' and self._found(r)]
        assert malos == []

    def test_se_consulto_a_todos_los_ip_y_dominios(self):
        faltan = [r['value'] for r in DATASET if r['type'] in ('ip', 'domain') and self._found(r) is None]
        assert faltan == []

    def test_control_encuentra_a_los_maliciosos_de_threatfox(self):
        """Sin este control, 'cero falsos positivos' también lo cumpliría un cliente que nunca encuentra nada."""
        hits = [r for r in DATASET if r['label_source'] == 'threatfox' and self._found(r)]
        assert len(hits) >= 12
