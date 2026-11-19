"""
CVE como tipo de IOC (WP3 de PLAN-FUSION): validación, clientes NVD/KEV/EPSS/Exploit-DB, scoring, MITRE y STIX.

Todas las respuestas de tests/fixtures/cve/ son REALES (capturadas el 2026-11-19). Cada garantía lleva su control.
"""
import json
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app import db
from app.models.ioc import IOC, IOCAnalysis
from app.services import cve_clients
from app.services.cve_attack_mapper import (
    ctid_coverage, cve_attack_techniques, heuristic_techniques,
)
from app.services.cve_clients import (
    CISAKEVClient, EPSSClient, ExploitDBClient, NVDClient, _CachedCatalog,
)
from app.services.llm_orchestrator import LLMOrchestrator
from app.utils.validators import (
    detect_ioc_type, extract_iocs_from_text, is_valid_cve, normalize_ioc_value, validate_ioc,
)

FX = Path(__file__).resolve().parents[2] / 'tests' / 'fixtures' / 'cve'


def _j(name):
    return json.loads((FX / name).read_text(encoding='utf-8'))


def _resp(status=200, payload=None, content=None, json_error=False):
    m = MagicMock()
    m.status_code = status
    if json_error:
        m.json.side_effect = ValueError('no json')
    else:
        m.json.return_value = payload
    m.content = content if content is not None else b''
    return m


@pytest.fixture
def app_ctx(app):
    with app.app_context():
        yield


@pytest.fixture(autouse=True)
def _limpia_catalogos():
    cve_clients._KEV.reset()
    cve_clients._EXPLOITDB.reset()
    yield
    cve_clients._KEV.reset()
    cve_clients._EXPLOITDB.reset()


ORCH = LLMOrchestrator.__new__(LLMOrchestrator)


# ============================================================================ VALIDACIÓN

class TestValidacion:
    @pytest.mark.parametrize('v', ['CVE-2021-44228', 'cve-2021-44228', 'Cve-2024-3094', 'CVE-2024-1234567', 'CVE-1999-0001'])
    def test_validos(self, v):
        assert is_valid_cve(v) and detect_ioc_type(v) == 'cve' and validate_ioc(v, 'cve') == (True, '')

    @pytest.mark.parametrize('v', ['CVE-21-1', 'CVE-2021-123', 'CVE2021-44228', 'CVE-2021-', 'CVE-2021-44228x',
                                   'XCVE-2021-44228', 'example.org', '', None, 5])
    def test_invalidos(self, v):
        assert not is_valid_cve(v)
        if isinstance(v, str):
            assert detect_ioc_type(v) != 'cve'

    def test_el_espacio_alrededor_se_tolera(self):
        assert is_valid_cve(' CVE-2021-44228 ') and detect_ioc_type('CVE-2021-44228 ') == 'cve'

    def test_validate_ioc_rechaza_formato_malo(self):
        ok, msg = validate_ioc('CVE-21-1', 'cve')
        assert not ok and 'CVE' in msg

    def test_normalizacion(self):
        assert normalize_ioc_value('cve-2021-44228 ', 'cve') == 'CVE-2021-44228'
        assert normalize_ioc_value('Example.ORG', 'domain') == 'Example.ORG'           # otros tipos intactos
        assert normalize_ioc_value('AbC', 'hash') == 'AbC'

    def test_extraccion_en_texto_libre(self):
        found = extract_iocs_from_text('mira cve-2021-44228 y CVE-2024-3094, ver https://x.io/a, repetido CVE-2021-44228')
        cves = [v for v, t in found if t == 'cve']
        assert cves == ['CVE-2021-44228', 'CVE-2024-3094']                              # mayúsculas y sin duplicados

    def test_el_orquestador_detecta_cve_en_el_chat(self, app_ctx):
        o = LLMOrchestrator()
        assert o._detect_ioc_type('cve-2021-44228') == 'cve'
        assert o._extract_ioc_from_message('analiza cve-2021-44228 por favor') == ('CVE-2021-44228', 'cve')
        assert o._extract_ioc_from_message('analiza 8.8.8.8') == ('8.8.8.8', 'ip')       # control: no rompe lo demás


# ============================================================================ NVD

class TestNVD:
    def test_log4shell_real(self, app_ctx):
        with patch.object(cve_clients, 'http_get', return_value=_resp(200, _j('nvd_log4shell.json'))):
            r = NVDClient().check_cve('CVE-2021-44228')
        assert r['found'] and r['id'] == 'CVE-2021-44228' and r['vuln_status'] == 'Analyzed'
        assert r['cvss_version'] == '3.1' and r['cvss_score'] == 10.0 and r['cvss_severity'] == 'CRITICAL'
        assert r['attack_vector'] == 'NETWORK' and r['privileges_required'] == 'NONE' and r['user_interaction'] == 'NONE'
        assert 'CWE-502' in r['cwes'] and r['exploit_reference_count'] > 0 and r['cisa_exploit_add'] == '2021-12-10'

    def test_otro_cve_local_con_privilegios(self, app_ctx):
        with patch.object(cve_clients, 'http_get', return_value=_resp(200, _j('nvd_other.json'))):
            r = NVDClient().check_cve('CVE-2026-0001')
        assert r['found'] and r['attack_vector'] == 'LOCAL' and r['privileges_required'] == 'LOW'
        assert r['exploit_reference_count'] == 0

    def test_inexistente_es_no_encontrado_no_error(self, app_ctx):
        with patch.object(cve_clients, 'http_get', return_value=_resp(200, _j('nvd_missing.json'))):
            assert NVDClient().check_cve('CVE-2099-99999') == {'found': False}

    @pytest.mark.parametrize('payload', [{'foo': 'bar'}, [], {'vulnerabilities': 'x'}, {'vulnerabilities': [{'nope': 1}]}])
    def test_forma_inesperada_es_error_visible(self, app_ctx, payload):
        """Un 200 con otra forma NO es 'sin datos': la API pudo cambiar."""
        with patch.object(cve_clients, 'http_get', return_value=_resp(200, payload)):
            r = NVDClient().check_cve('CVE-2021-44228')
        assert 'error' in r and 'found' not in r

    def test_200_sin_json_es_error(self, app_ctx):
        with patch.object(cve_clients, 'http_get', return_value=_resp(200, json_error=True)):
            assert 'error' in NVDClient().check_cve('CVE-2021-44228')

    @pytest.mark.parametrize('status', [403, 429])
    def test_limite_de_nvd_se_explica(self, app_ctx, status):
        with patch.object(cve_clients, 'http_get', return_value=_resp(status)):
            assert 'límite' in NVDClient().check_cve('CVE-2021-44228')['error']

    def test_http_500(self, app_ctx):
        with patch.object(cve_clients, 'http_get', return_value=_resp(500)):
            assert NVDClient().check_cve('CVE-2021-44228') == {'error': 'HTTP 500'}

    def test_excepcion_de_red(self, app_ctx):
        with patch.object(cve_clients, 'http_get', side_effect=OSError('sin red')):
            assert 'sin red' in NVDClient().check_cve('CVE-2021-44228')['error']

    def test_prefiere_la_metrica_primary_sobre_la_secondary(self, app_ctx):
        base = _j('nvd_log4shell.json')
        m = base['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]
        sec = json.loads(json.dumps(m))
        sec['type'] = 'Secondary'
        sec['cvssData']['baseScore'] = 1.0                        # una CNA que puntúa distinto, y va PRIMERA
        base['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'] = [sec, m]
        with patch.object(cve_clients, 'http_get', return_value=_resp(200, base)):
            assert NVDClient().check_cve('CVE-2021-44228')['cvss_score'] == 10.0

    def test_control_sin_primary_usa_la_primera(self, app_ctx):
        base = _j('nvd_log4shell.json')
        base['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['type'] = 'Secondary'
        with patch.object(cve_clients, 'http_get', return_value=_resp(200, base)):
            assert NVDClient().check_cve('CVE-2021-44228')['cvss_score'] == 10.0

    def test_cvss_v2_trae_la_severidad_fuera_de_cvssdata(self, app_ctx):
        base = _j('nvd_log4shell.json')
        c = base['vulnerabilities'][0]['cve']
        c['metrics'] = {'cvssMetricV2': [dict(c['metrics']['cvssMetricV2'][0], baseSeverity='HIGH')]}
        with patch.object(cve_clients, 'http_get', return_value=_resp(200, base)):
            r = NVDClient().check_cve('CVE-2021-44228')
        assert r['cvss_version'] == '2.0' and r['cvss_severity'] == 'HIGH' and r['attack_vector'] == 'NETWORK'

    def test_sin_metricas(self, app_ctx):
        base = _j('nvd_log4shell.json')
        base['vulnerabilities'][0]['cve']['metrics'] = {}
        with patch.object(cve_clients, 'http_get', return_value=_resp(200, base)):
            r = NVDClient().check_cve('CVE-2021-44228')
        assert r['found'] and r['cvss_score'] is None

    def test_rechazado(self, app_ctx):
        base = _j('nvd_log4shell.json')
        base['vulnerabilities'][0]['cve']['vulnStatus'] = 'Rejected'
        with patch.object(cve_clients, 'http_get', return_value=_resp(200, base)):
            assert NVDClient().check_cve('CVE-2021-44228')['rejected'] is True

    def test_envia_la_clave_si_existe(self, app, app_ctx):
        app.config['API_KEYS']['nvd'] = 'k-de-prueba'
        try:
            with patch.object(cve_clients, 'http_get', return_value=_resp(200, _j('nvd_missing.json'))) as g:
                NVDClient().check_cve('CVE-2099-99999')
            assert g.call_args.kwargs['headers'] == {'apiKey': 'k-de-prueba'}
        finally:
            app.config['API_KEYS']['nvd'] = None
        with patch.object(cve_clients, 'http_get', return_value=_resp(200, _j('nvd_missing.json'))) as g:
            NVDClient().check_cve('CVE-2099-99999')
        assert g.call_args.kwargs['headers'] == {}


# ============================================================================ KEV

class TestKEV:
    def test_encontrado(self, app_ctx):
        with patch.object(cve_clients, 'http_get', return_value=_resp(200, _j('kev_catalog_trimmed.json'))):
            r = CISAKEVClient().check_cve('cve-2021-44228')                      # no distingue mayúsculas
        assert r['found'] and r['in_kev'] and r['vendor_project'] == 'Apache' and r['product'] == 'Log4j2'
        assert r['known_ransomware'] is True and r['date_added'] == '2021-12-10' and 'CWE-502' in r['cwes']
        assert r['catalog_version'] and r['stale'] is False

    def test_ransomware_desconocido_es_false(self, app_ctx):
        with patch.object(cve_clients, 'http_get', return_value=_resp(200, _j('kev_catalog_trimmed.json'))):
            assert CISAKEVClient().check_cve('CVE-2024-10441')['known_ransomware'] is False

    def test_no_en_kev(self, app_ctx):
        with patch.object(cve_clients, 'http_get', return_value=_resp(200, _j('kev_catalog_trimmed.json'))):
            r = CISAKEVClient().check_cve('CVE-2026-0001')
        assert r['found'] is False and r['in_kev'] is False and r['catalog_count']

    def test_descarga_una_sola_vez(self, app_ctx):
        with patch.object(cve_clients, 'http_get', return_value=_resp(200, _j('kev_catalog_trimmed.json'))) as g:
            for c in ('CVE-2021-44228', 'CVE-2026-0001', 'CVE-2024-10441'):
                CISAKEVClient().check_cve(c)
        assert g.call_count == 1

    @pytest.mark.parametrize('payload', [{'foo': 1}, [], {'vulnerabilities': 'x'}, {'vulnerabilities': [{'sin': 'cveID'}]}])
    def test_forma_inesperada_es_error(self, app_ctx, payload):
        with patch.object(cve_clients, 'http_get', return_value=_resp(200, payload)):
            r = CISAKEVClient().check_cve('CVE-2021-44228')
        assert 'error' in r and 'found' not in r

    def test_http_error_sin_copia_anterior_es_error(self, app_ctx):
        with patch.object(cve_clients, 'http_get', return_value=_resp(503)):
            assert 'error' in CISAKEVClient().check_cve('CVE-2021-44228')

    def test_si_el_refresco_falla_sirve_la_copia_anterior_marcada(self, app_ctx):
        with patch.object(cve_clients, 'http_get', return_value=_resp(200, _j('kev_catalog_trimmed.json'))):
            CISAKEVClient().check_cve('CVE-2021-44228')
        cve_clients._KEV._loaded_at = 0                                     # caduca el TTL
        with patch.object(cve_clients, 'http_get', return_value=_resp(503)):
            r = CISAKEVClient().check_cve('CVE-2021-44228')
        assert r['found'] and r['stale'] is True


class TestCatalogoCacheado:
    def test_ttl_y_descarga_unica_bajo_concurrencia(self):
        n = {'c': 0}

        def loader():
            n['c'] += 1
            time.sleep(0.15)
            return {'v': n['c']}

        cat = _CachedCatalog('t', 3600, loader)
        out = []
        ts = [threading.Thread(target=lambda: out.append(cat.get()[0]['v'])) for _ in range(8)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        assert n['c'] == 1 and set(out) == {1}

    def test_expira_y_recarga(self):
        n = {'c': 0}
        cat = _CachedCatalog('t', 3600, lambda: n.__setitem__('c', n['c'] + 1) or {'v': n['c']})
        cat.get()
        cat._loaded_at = 0
        assert cat.get()[0]['v'] == 2

    def test_stale_si_falla_y_hay_copia(self):
        cat = _CachedCatalog('t', 3600, lambda: {'v': 1})
        cat.get()
        cat._loaded_at = 0
        cat._loader = lambda: (_ for _ in ()).throw(RuntimeError('caído'))
        data, stale = cat.get()
        assert data == {'v': 1} and stale is True

    def test_sin_copia_propaga_el_error(self):
        cat = _CachedCatalog('t', 3600, lambda: (_ for _ in ()).throw(RuntimeError('caído')))
        with pytest.raises(RuntimeError):
            cat.get()


# ============================================================================ EPSS

class TestEPSS:
    def test_log4shell_real(self, app_ctx):
        with patch.object(cve_clients, 'http_get', return_value=_resp(200, _j('epss_log4shell.json'))):
            r = EPSSClient().check_cve('CVE-2021-44228')
        assert r['found'] and r['epss'] > 0.99 and r['percentile'] == 1.0 and r['date']

    def test_sin_puntuar_es_no_encontrado(self, app_ctx):
        with patch.object(cve_clients, 'http_get', return_value=_resp(200, _j('epss_missing.json'))):
            assert EPSSClient().check_cve('CVE-2099-99999') == {'found': False}

    @pytest.mark.parametrize('payload', [{'foo': 1}, [], {'data': 'x'}, {'data': [{'cve': 'X'}]},
                                         {'data': [{'epss': 'abc', 'percentile': '0.1'}]}])
    def test_forma_inesperada_es_error(self, app_ctx, payload):
        with patch.object(cve_clients, 'http_get', return_value=_resp(200, payload)):
            assert 'error' in EPSSClient().check_cve('CVE-2021-44228')

    def test_http_error(self, app_ctx):
        with patch.object(cve_clients, 'http_get', return_value=_resp(500)):
            assert EPSSClient().check_cve('CVE-2021-44228') == {'error': 'HTTP 500'}


# ============================================================================ Exploit-DB

def _csv_resp(name='exploitdb_excerpt.csv'):
    return _resp(200, content=(FX / name).read_bytes())


class TestExploitDB:
    def test_log4shell_desde_el_dataset_oficial(self, app_ctx):
        with patch.object(cve_clients, 'http_get', return_value=_csv_resp()):
            r = ExploitDBClient().check_cve('CVE-2021-44228')
        assert r['found'] and r['exploit_count'] == 3
        assert {e['id'] for e in r['exploits']} == {'51183', '50592', '50590'}
        fechas = [e['date_published'] for e in r['exploits']]
        assert fechas == sorted(fechas, reverse=True)                      # el más reciente primero
        assert all(e['title'] and e['platform'] for e in r['exploits'])    # campos reales, no vacíos

    def test_una_fila_con_varios_cve_se_indexa_por_cada_uno(self, app_ctx):
        with patch.object(cve_clients, 'http_get', return_value=_csv_resp()):
            assert ExploitDBClient().check_cve('CVE-2005-2236')['exploit_count'] == 1
            assert ExploitDBClient().check_cve('CVE-2005-2232')['exploit_count'] == 1

    def test_sin_exploit_es_no_encontrado(self, app_ctx):
        with patch.object(cve_clients, 'http_get', return_value=_csv_resp()):
            assert ExploitDBClient().check_cve('CVE-2099-99999') == {'found': False, 'exploit_count': 0, 'stale': False}

    def test_las_filas_sin_cve_no_se_indexan(self, app_ctx):
        with patch.object(cve_clients, 'http_get', return_value=_csv_resp()):
            ExploitDBClient().check_cve('CVE-2021-44228')
        index, _ = cve_clients._EXPLOITDB.get()
        assert all(k.startswith('CVE-') for k in index) and '25807' not in {e['id'] for v in index.values() for e in v}

    def test_columnas_inesperadas_es_error(self, app_ctx):
        with patch.object(cve_clients, 'http_get', return_value=_resp(200, content=b'a,b,c\n1,2,3\n')):
            assert 'error' in ExploitDBClient().check_cve('CVE-2021-44228')

    def test_http_error(self, app_ctx):
        with patch.object(cve_clients, 'http_get', return_value=_resp(404)):
            assert 'error' in ExploitDBClient().check_cve('CVE-2021-44228')

    def test_descarga_una_sola_vez(self, app_ctx):
        with patch.object(cve_clients, 'http_get', return_value=_csv_resp()) as g:
            for c in ('CVE-2021-44228', 'CVE-2005-2236', 'CVE-2099-99999'):
                ExploitDBClient().check_cve(c)
        assert g.call_count == 1


# ============================================================================ SCORING

def _real(cve_nvd='nvd_log4shell.json', kev=True, epss='epss_log4shell.json', edb=True, app=None):
    """Resultados de las 4 APIs sobre respuestas reales, como los entregan los clientes."""
    with patch.object(cve_clients, 'http_get', return_value=_resp(200, _j(cve_nvd))):
        nvd = NVDClient().check_cve('CVE-2021-44228')
    cve_clients._KEV.reset()
    with patch.object(cve_clients, 'http_get', return_value=_resp(200, _j('kev_catalog_trimmed.json'))):
        k = CISAKEVClient().check_cve('CVE-2021-44228' if kev else 'CVE-2026-0001')
    with patch.object(cve_clients, 'http_get', return_value=_resp(200, _j(epss))):
        e = EPSSClient().check_cve('CVE-2021-44228')
    cve_clients._EXPLOITDB.reset()
    with patch.object(cve_clients, 'http_get', return_value=_csv_resp()):
        x = ExploitDBClient().check_cve('CVE-2021-44228' if edb else 'CVE-2099-99999')
    return {'nvd': nvd, 'cisa_kev': k, 'epss': e, 'exploitdb': x}


class TestScoring:
    def test_log4shell_es_critico(self, app_ctx):
        res = _real()
        s = ORCH._calculate_enhanced_score(res, {})
        assert s == 100 and ORCH._determine_risk_level(s) == 'CRÍTICO'

    def test_control_sin_kev_ni_exploits_baja_mucho(self, app_ctx):
        """Una vuln grave PERO sin explotación conocida no es CRÍTICA: lo que pesa es que se explote."""
        res = _real(kev=False, edb=False)
        res['epss'] = {'found': True, 'epss': 0.001, 'percentile': 0.1}
        s = ORCH._calculate_enhanced_score(res, {})
        assert s < 50 and ORCH._determine_risk_level(s) in ('MEDIO', 'BAJO')

    @pytest.mark.parametrize('api,res,esperado', [
        ('cisa_kev', {'found': True, 'in_kev': True, 'known_ransomware': False}, 40),
        ('cisa_kev', {'found': True, 'in_kev': True, 'known_ransomware': True}, 50),
        ('cisa_kev', {'found': False, 'in_kev': False}, 0),
        ('nvd', {'found': True, 'cvss_score': 9.8}, 30), ('nvd', {'found': True, 'cvss_score': 9.0}, 30),
        ('nvd', {'found': True, 'cvss_score': 8.9}, 20), ('nvd', {'found': True, 'cvss_score': 7.0}, 20),
        ('nvd', {'found': True, 'cvss_score': 6.9}, 10), ('nvd', {'found': True, 'cvss_score': 4.0}, 10),
        ('nvd', {'found': True, 'cvss_score': 3.9}, 0), ('nvd', {'found': True, 'cvss_score': None}, 0),
        ('nvd', {'found': True, 'cvss_score': 9.8, 'exploit_reference_count': 2}, 35),
        ('nvd', {'found': True, 'cvss_score': 9.8, 'rejected': True}, 0),         # un CVE rechazado no puntúa
        ('nvd', {'found': False}, 0),
        ('epss', {'found': True, 'epss': 0.5}, 30), ('epss', {'found': True, 'epss': 0.49}, 20),
        ('epss', {'found': True, 'epss': 0.1}, 20), ('epss', {'found': True, 'epss': 0.09}, 8),
        ('epss', {'found': True, 'epss': 0.01}, 8), ('epss', {'found': True, 'epss': 0.0099}, 0), ('epss', {'found': False}, 0),
        ('exploitdb', {'found': True, 'exploit_count': 2}, 10), ('exploitdb', {'found': False, 'exploit_count': 0}, 0),
    ])
    def test_puntos_por_senal(self, api, res, esperado):
        assert ORCH._cve_points(api, res) == esperado

    def test_cvss_9_8_solo_es_medio_no_critico(self):
        s = ORCH._calculate_enhanced_score({'nvd': {'found': True, 'cvss_score': 9.8}}, {})
        assert s == 30 and ORCH._determine_risk_level(s) == 'MEDIO'

    def test_una_api_que_falla_no_puntua(self):
        assert ORCH._calculate_enhanced_score({'cisa_kev': {'error': 'HTTP 500', 'in_kev': True}}, {}) == 0


# ============================================================================ MITRE

class TestMitre:
    def test_ctid_se_cargo(self):
        assert ctid_coverage() > 800

    def test_mapeo_curado_tiene_prioridad_y_procedencia(self):
        r = cve_attack_techniques('cve-2019-15976', {'nvd': {'found': True, 'attack_vector': 'LOCAL', 'privileges_required': 'LOW'}})
        assert set(r.values()) == {'ctid'} and {'T1068', 'T1190'} <= set(r)

    def test_log4shell_no_esta_en_ctid_y_se_usa_la_heuristica_etiquetada(self, app_ctx):
        res = _real()
        r = cve_attack_techniques('CVE-2021-44228', res)
        assert r == {'T1190': 'heuristic_cvss'}

    @pytest.mark.parametrize('av,ui,pr,esperado', [
        ('NETWORK', 'NONE', 'NONE', ['T1190']),
        ('NETWORK', 'REQUIRED', 'NONE', []),                  # T1203 se probó y se eliminó: sin respaldo en CTID
        ('NETWORK', 'ACTIVE', 'NONE', []),                    # CVSS 4.0
        ('NETWORK', 'NONE', 'LOW', []),                        # remoto pero autenticado: sin regla
        ('LOCAL', 'NONE', 'LOW', []),                          # T1068 se probó y se eliminó: sin respaldo en CTID
        ('PHYSICAL', 'NONE', 'HIGH', []),
        ('LOCAL', 'NONE', 'NONE', []),
        ('ADJACENT_NETWORK', None, 'NONE', ['T1190']),
        (None, None, None, []),
    ])
    def test_reglas_de_la_heuristica(self, av, ui, pr, esperado):
        nvd = {'found': True, 'attack_vector': av, 'user_interaction': ui, 'privileges_required': pr}
        assert heuristic_techniques(nvd) == esperado

    @pytest.mark.parametrize('nvd', [None, {}, {'found': False}, {'error': 'x'}, 'texto'])
    def test_sin_datos_de_nvd_no_inventa(self, nvd):
        assert heuristic_techniques(nvd) == []
        assert cve_attack_techniques('CVE-2099-99999', {'nvd': nvd}) == {}

    def test_el_flujo_completo_fusiona_y_expone_la_procedencia(self, app_ctx):
        o = LLMOrchestrator()
        o._clients_initialized = True
        o.api_clients = {n: object() for n in ('cisa_kev', 'nvd', 'epss', 'exploitdb')}
        res = _real()
        with patch.object(o, '_execute_apis', return_value=res), patch.object(o, '_synthesize_with_llm', return_value={}):
            r = o.analyze_with_intelligence('CVE-2021-44228', 'cve', use_llm_planning=False)
        assert 'T1190' in r['mitre_techniques'] and r['mitre_provenance'] == {'T1190': 'heuristic_cvss'}
        assert r['risk_level'] == 'CRÍTICO' and r['api_coverage']['incomplete'] is False
        assert r['selected_apis'] == ['cisa_kev', 'nvd', 'epss', 'exploitdb']

    def test_control_un_ip_no_pasa_por_el_mapeo_de_cve(self, app_ctx):
        o = LLMOrchestrator()
        o._clients_initialized = True
        o.api_clients = {'abuseipdb': object()}
        with patch.object(o, '_execute_apis', return_value={'abuseipdb': {'abuse_confidence_score': 0}}), \
                patch.object(o, '_synthesize_with_llm', return_value={}):
            r = o.analyze_with_intelligence('8.8.8.8', 'ip', profile_apis=['abuseipdb'])
        assert r['mitre_provenance'] == {}


# ============================================================================ CABLEADO

class TestCableado:
    def test_las_cuatro_apis_son_columnas_y_compatibles_solo_con_cve(self, app_ctx):
        o = LLMOrchestrator.__new__(LLMOrchestrator)
        for api in ('nvd', 'cisa_kev', 'epss', 'exploitdb'):
            assert api in IOCAnalysis.api_source_names()
            assert o._is_api_compatible(api, 'cve')
            assert not any(o._is_api_compatible(api, t) for t in ('ip', 'domain', 'url', 'hash'))

    def test_la_estrategia_de_cve_solo_usa_apis_que_existen_y_son_compatibles(self, app_ctx):
        o = LLMOrchestrator()
        assert o.strategies['cve'] and all(a in IOCAnalysis.api_source_names() and o._is_api_compatible(a, 'cve')
                                           for a in o.strategies['cve'])

    def test_los_demas_tipos_no_consultan_apis_de_cve(self, app_ctx):
        o = LLMOrchestrator()
        for t in ('ip', 'domain', 'url', 'hash'):
            assert not set(o.strategies[t]) & {'nvd', 'cisa_kev', 'epss', 'exploitdb'}

    def test_el_despacho_resuelve_las_4_apis_de_cve(self):
        from app.services.async_executor import _resolve_method
        for api in ('nvd', 'cisa_kev', 'epss', 'exploitdb'):
            assert _resolve_method(api, MagicMock(), 'CVE-2021-44228', 'cve') is not None, api

    def test_el_despacho_no_resuelve_apis_de_cve_para_otros_tipos(self):
        from app.services.async_executor import _resolve_method
        assert _resolve_method('nvd', MagicMock(), '8.8.8.8', 'ip') is None

    def test_circuit_breaker_y_limites_configurados(self, app):
        from app.utils.circuit_breaker import _API_CONFIG
        for api in ('nvd', 'cisa_kev', 'epss', 'exploitdb'):
            assert api in _API_CONFIG and api in app.config['API_LIMITS']
        assert 'nvd' in app.config['API_KEYS']                      # clave OPCIONAL: existe la entrada aunque sea None

    def test_nvd_sin_clave_no_aparece_como_sin_configurar(self, analyst_client):
        """La clave de NVD es opcional: sin ella funciona (con límite menor), así que no es 'No config'."""
        apis = analyst_client.get('/api/v2/apis/status').get_json()['apis']
        for api in ('nvd', 'cisa_kev', 'epss', 'exploitdb'):
            assert apis[api]['is_configured'] is True, api

    def test_ttl_de_cache_para_cve(self):
        from app.services.ioc_cache import CACHE_TTL_BY_TYPE, _get_effective_ttl
        assert CACHE_TTL_BY_TYPE['cve'] == 6 and _get_effective_ttl('LIMPIO', 'cve') == 6 and _get_effective_ttl('CRÍTICO', 'cve') == 1


class TestPlanificadorSoloOfreceApisCompatibles:
    def _orq(self, app_ctx):
        o = LLMOrchestrator()
        o._clients_initialized = True
        o.api_clients = {n: object() for n in ('virustotal', 'abuseipdb', 'nvd', 'cisa_kev', 'epss', 'exploitdb', 'malwarebazaar')}
        return o

    def test_el_prompt_solo_lista_apis_de_cve(self, app_ctx):
        o = self._orq(app_ctx)
        with patch.object(o, 'select_provider', return_value=object()),                 patch.object(o, '_call_llm', return_value=['nvd', 'epss']) as call:
            assert o._plan_analysis_with_llm('CVE-2021-44228', 'cve', '') == ['nvd', 'epss']
        prompt = call.call_args.args[1]
        assert 'nvd' in prompt and 'cisa_kev' in prompt and 'abuseipdb' not in prompt and 'malwarebazaar' not in prompt

    def test_si_el_llm_elige_incompatibles_cae_a_la_estrategia(self, app_ctx):
        """Control del fallo: antes quedaba vacío y /analyze devolvía 502 con una estrategia que sí funcionaba."""
        o = self._orq(app_ctx)
        with patch.object(o, 'select_provider', return_value=object()),                 patch.object(o, '_call_llm', return_value=['virustotal', 'abuseipdb', 'malwarebazaar']):
            assert o._plan_analysis_with_llm('CVE-2021-44228', 'cve', '') == o.strategies['cve']

    def test_control_para_una_ip_sigue_ofreciendo_sus_apis(self, app_ctx):
        o = self._orq(app_ctx)
        with patch.object(o, 'select_provider', return_value=object()),                 patch.object(o, '_call_llm', return_value=['abuseipdb', 'nvd']):
            assert o._plan_analysis_with_llm('8.8.8.8', 'ip', '') == ['abuseipdb']


class TestApiDataKwargs:
    def test_cubre_exactamente_las_columnas_data(self, app):
        kw = IOCAnalysis.api_data_kwargs({})
        assert set(kw) == {c.name for c in IOCAnalysis.__table__.columns if c.name.endswith('_data')}
        assert {'nvd_data', 'cisa_kev_data', 'epss_data', 'exploitdb_data', 'crtsh_data', 'virustotal_data'} <= set(kw)

    def test_reparte_cada_resultado_a_su_columna_e_ignora_lo_desconocido(self, app):
        kw = IOCAnalysis.api_data_kwargs({'nvd': {'a': 1}, 'epss': {'b': 2}, 'api_inventada': {'c': 3}})
        assert kw['nvd_data'] == {'a': 1} and kw['epss_data'] == {'b': 2} and kw['virustotal_data'] is None
        assert 'api_inventada_data' not in kw

    def test_none_no_rompe(self, app):
        assert IOCAnalysis.api_data_kwargs(None)['nvd_data'] is None


# ============================================================================ RUTA

RES = {'confidence_score': 100, 'risk_level': 'CRÍTICO', 'llm_analysis': {'recommendations': ['parchear']},
       'mitre_techniques': ['T1190'], 'mitre_provenance': {'T1190': 'heuristic_cvss'}, 'processing_time': 0.1,
       'timestamp': '2026-11-19T00:00:00+00:00', 'sources_used': ['cisa_kev', 'nvd'],
       'api_results': {'cisa_kev': {'found': True, 'in_kev': True}, 'nvd': {'found': True, 'cvss_score': 10.0},
                       'epss': {'found': True, 'epss': 0.99}, 'exploitdb': {'found': True, 'exploit_count': 3}},
       'api_coverage': {'ok': 4, 'failed': [], 'total': 4, 'incomplete': False}}


def _analizar(client, ioc, **extra):
    with patch('app.routes.api_v2_routes.get_orchestrator') as o, patch('app.services.ioc_cache.get_cached_analysis', return_value=None):
        o.return_value.analyze_with_intelligence.return_value = RES
        r = client.post('/api/v2/analyze/enhanced', json={'ioc': ioc, 'use_llm_planning': False, **extra})
        return r, o.return_value.analyze_with_intelligence


class TestRuta:
    def test_minusculas_se_normaliza_y_se_detecta_el_tipo(self, app, db_session, analyst_client):
        r, mock = _analizar(analyst_client, 'cve-2021-44228')
        assert r.status_code == 200 and r.get_json()['type'] == 'cve' and r.get_json()['ioc'] == 'CVE-2021-44228'
        assert mock.call_args.kwargs['ioc'] == 'CVE-2021-44228' and mock.call_args.kwargs['ioc_type'] == 'cve'
        assert IOC.query.filter_by(value='CVE-2021-44228', ioc_type='cve').count() == 1
        assert IOC.query.filter_by(value='cve-2021-44228').count() == 0

    def test_se_guardan_las_cuatro_columnas(self, app, db_session, analyst_client):
        r, _ = _analizar(analyst_client, 'CVE-2021-44228')
        a = db.session.get(IOCAnalysis, r.get_json()['analysis_id'])
        assert a.cisa_kev_data['in_kev'] and a.nvd_data['cvss_score'] == 10.0 and a.epss_data['epss'] == 0.99
        assert a.exploitdb_data['exploit_count'] == 3 and a.virustotal_data is None

    def test_la_respuesta_expone_la_procedencia_de_las_tecnicas(self, app, db_session, analyst_client):
        r, _ = _analizar(analyst_client, 'CVE-2021-44228')
        j = r.get_json()
        assert j['mitre_techniques'] == ['T1190'] and j['mitre_provenance'] == {'T1190': 'heuristic_cvss'}

    def test_to_dict_incluye_las_apis_de_cve(self, app, db_session, analyst_client):
        r, _ = _analizar(analyst_client, 'CVE-2021-44228')
        d = db.session.get(IOCAnalysis, r.get_json()['analysis_id']).to_dict()
        assert d['nvd']['cvss_score'] == 10.0 and d['cisa_kev']['in_kev'] and d['epss']['epss'] == 0.99

    def test_dos_variantes_de_mayusculas_son_un_solo_ioc(self, app, db_session, analyst_client):
        _analizar(analyst_client, 'cve-2021-44228')
        _analizar(analyst_client, 'CVE-2021-44228')
        assert IOC.query.filter_by(ioc_type='cve').count() == 1

    @pytest.mark.parametrize('ioc', ['CVE-21-1', 'CVE-2021-12'])
    def test_formato_invalido_con_tipo_explicito_es_400(self, analyst_client, ioc):
        r, mock = _analizar(analyst_client, ioc, type='cve')
        assert r.status_code in (400, 422) and not mock.called

    def test_control_un_cve_no_se_confunde_con_un_dominio(self, app, db_session, analyst_client):
        r, _ = _analizar(analyst_client, 'CVE-2021-44228')
        assert r.get_json()['type'] != 'domain'

    def test_perfil_de_cve_fija_las_apis(self, app, db_session, analyst_client):
        from app.services.profile_service import ensure_system_profiles
        from app.models.profile import InvestigationProfile
        ensure_system_profiles()
        p = InvestigationProfile.query.filter_by(name='CVE: explotación rápida').one()
        r, mock = _analizar(analyst_client, 'CVE-2021-44228', profile_id=p.id)
        assert r.status_code == 200 and mock.call_args.kwargs['profile_apis'] == ['cisa_kev', 'epss']

    def test_un_perfil_de_ip_no_sirve_para_un_cve(self, app, db_session, analyst_client):
        from app.services.profile_service import ensure_system_profiles
        from app.models.profile import InvestigationProfile
        ensure_system_profiles()
        p = InvestigationProfile.query.filter_by(ioc_type='ip').first()
        assert _analizar(analyst_client, 'CVE-2021-44228', profile_id=p.id)[0].status_code == 400


# ============================================================================ STIX

class TestStix:
    def _datos(self, db_session):
        ioc = IOC(value='CVE-2021-44228', ioc_type='cve')
        db_session.session.add(ioc)
        db_session.session.commit()
        a = IOCAnalysis(ioc_id=ioc.id, confidence_score=100, risk_level='CRÍTICO', mitre_techniques=['T1190'],
                        sources_used=['nvd'], nvd_data={'description': 'RCE en Log4j'},
                        cisa_kev_data={'in_kev': True}, epss_data={'epss': 0.99})
        db_session.session.add(a)
        db_session.session.commit()
        return ioc, a

    def test_un_cve_es_una_vulnerability_no_un_indicator(self, app, db_session):
        from app.services.stix_exporter import STIXExporter
        ioc, a = self._datos(db_session)
        bundle = STIXExporter().export_analysis(a.id)
        tipos = [o['type'] for o in bundle['objects']]
        assert 'vulnerability' in tipos and 'indicator' not in tipos
        v = next(o for o in bundle['objects'] if o['type'] == 'vulnerability')
        assert v['name'] == 'CVE-2021-44228' and v['external_references'][0] == {'source_name': 'cve', 'external_id': 'CVE-2021-44228'}
        assert v['description'] == 'RCE en Log4j' and v['x_soc_agent_risk']['in_cisa_kev'] is True

    def test_la_tecnica_apunta_a_la_vulnerabilidad(self, app, db_session):
        from app.services.stix_exporter import STIXExporter
        ioc, a = self._datos(db_session)
        objs = STIXExporter().export_analysis(a.id)['objects']
        v = next(o for o in objs if o['type'] == 'vulnerability')
        ap = next(o for o in objs if o['type'] == 'attack-pattern')
        rel = next(o for o in objs if o['type'] == 'relationship')
        assert rel['relationship_type'] == 'targets' and rel['source_ref'] == ap['id'] and rel['target_ref'] == v['id']

    def test_control_una_ip_sigue_siendo_un_indicator(self, app, db_session):
        from app.services.stix_exporter import STIXExporter
        ioc = IOC(value='198.51.100.9', ioc_type='ip')
        db_session.session.add(ioc)
        db_session.session.commit()
        a = IOCAnalysis(ioc_id=ioc.id, confidence_score=80, risk_level='ALTO', mitre_techniques=['T1071'])
        db_session.session.add(a)
        db_session.session.commit()
        objs = STIXExporter().export_analysis(a.id)['objects']
        assert 'indicator' in [o['type'] for o in objs] and 'vulnerability' not in [o['type'] for o in objs]
        rel = next(o for o in objs if o['type'] == 'relationship')
        assert rel['relationship_type'] == 'indicates'
