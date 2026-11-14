"""
Tests de parser con la FORMA REAL de las respuestas (verificadas contra las APIs
en vivo, 2026-11-13). Los mocks anteriores usaban formas inventadas y por eso no
detectaron que ThreatFox, Hybrid Analysis, Censys y Criminal IP estaban rotos.
"""
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(scope='function')
def app_ctx(app):
    with app.app_context():
        yield


def resp(status, data):
    m = MagicMock()
    m.status_code = status
    m.json.return_value = data
    return m


class TestThreatFoxUrl:
    def test_base_url_termina_en_barra(self, app_ctx):
        # Sin la barra final el servidor redirige y el POST se vuelve GET -> 405
        from app.services.new_api_clients import ThreatFoxClient
        assert ThreatFoxClient().base_url.endswith('/api/v1/')

    def test_post_usa_url_con_barra(self, app_ctx):
        from app.services.new_api_clients import ThreatFoxClient
        with patch('requests.post', return_value=resp(200, {'query_status': 'no_result', 'data': 'x'})) as p:
            result = ThreatFoxClient().search_ioc('1.1.1.1')
        assert p.call_args[0][0].endswith('/api/v1/')
        assert result == {'found': False}


class TestHybridAnalysisOverviewDict:
    def test_overview_dict_real(self, app_ctx):
        from app.services.new_api_clients import HybridAnalysisClient
        overview = {
            'sha256': '275a021b', 'last_file_name': 'eicar.com', 'threat_score': 100,
            'verdict': 'malicious', 'type': 'EICAR virus test files', 'vx_family': 'Eicar',
            'multiscan_result': 29, 'tags': ['eicar'],
        }
        with patch('requests.get', return_value=resp(200, overview)):
            r = HybridAnalysisClient().search_hash('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f')
        assert r['found'] is True
        assert r['verdict'] == 'malicious'
        assert r['threat_score'] == 100
        assert r['av_detect'] == 29
        assert r['submit_name'] == 'eicar.com'

    def test_dict_vacio_es_no_encontrado(self, app_ctx):
        from app.services.new_api_clients import HybridAnalysisClient
        with patch('requests.get', return_value=resp(200, {})):
            r = HybridAnalysisClient().search_hash('d41d8cd98f00b204e9800998ecf8427e')
        assert r['found'] is False


class TestCensysPlatformV3:
    def test_result_resource(self, app_ctx):
        from app.services.new_api_clients import CensysClient
        body = {'result': {'resource': {
            'ip': '8.8.8.8',
            'location': {'country': 'United States', 'city': 'Mountain View'},
            'autonomous_system': {'asn': 15169, 'name': 'GOOGLE'},
            'service_count': 2,
            'services': [
                {'port': 53, 'protocol': 'DNS', 'transport_protocol': 'tcp'},
                {'port': 443, 'protocol': 'HTTP', 'transport_protocol': 'tcp'},
            ],
        }, 'extensions': {}}}
        with patch('requests.get', return_value=resp(200, body)):
            r = CensysClient().check_ip('8.8.8.8')
        assert r['found'] is True
        assert r['services_count'] == 2
        assert r['services'][0]['service_name'] == 'DNS'
        assert r['autonomous_system']['asn'] == 15169
        assert r['location']['country'] == 'United States'

    def test_operating_system_none_no_rompe(self, app_ctx):
        from app.services.new_api_clients import CensysClient
        body = {'result': {'resource': {'ip': '1.2.3.4', 'operating_system': None, 'services': None}}}
        with patch('requests.get', return_value=resp(200, body)):
            r = CensysClient().check_ip('1.2.3.4')
        assert r['services_count'] == 0
        assert r['operating_system'] == {}


class TestCriminalIPFlat:
    TOR = {
        'status': 200, 'ip': '185.220.101.1',
        'issues': {'is_vpn': False, 'is_tor': True, 'is_proxy': False, 'is_hosting': False,
                   'is_scanner': False, 'is_snort': True, 'is_darkweb': False},
        'score': {'inbound': 'Critical', 'outbound': 'Moderate'},
        'whois': {'count': 1, 'data': [{'org_country_code': 'DE', 'city': 'Berlin',
                                        'org_name': 'Foo', 'as_name': 'AS-FOO'}]},
        'port': {'count': 1, 'data': [{'open_port_no': 443}]},
    }

    def test_parser_plano(self, app_ctx):
        from app.services.new_api_clients import CriminalIPClient
        with patch('requests.get', return_value=resp(200, self.TOR)):
            r = CriminalIPClient().check_ip('185.220.101.1')
        assert r['found'] is True
        assert r['score'] == 'Critical'
        assert r['is_tor'] is True
        assert r['is_malicious'] is True
        assert r['country'] == 'DE'
        assert r['open_ports'] == [443]
        assert 'is_tor' in r['issues']

    def test_whois_vacio(self, app_ctx):
        from app.services.new_api_clients import CriminalIPClient
        body = dict(self.TOR, whois={'count': 0, 'data': []}, port={'count': 0, 'data': []},
                    score={'inbound': 'Low', 'outbound': 'Low'})
        with patch('requests.get', return_value=resp(200, body)):
            r = CriminalIPClient().check_ip('9.9.9.9')
        assert r['country'] is None
        assert r['is_malicious'] is False
        assert r['open_ports'] == []

    def test_403_ip_restringida_no_es_error(self, app_ctx):
        from app.services.new_api_clients import CriminalIPClient
        with patch('requests.get', return_value=resp(403, {})):
            r = CriminalIPClient().check_ip('8.8.8.8')
        assert r['found'] is False and 'error' not in r

    def test_geo_desde_summary_si_whois_vacio(self, app_ctx):
        from app.services.new_api_clients import CriminalIPClient
        report = dict(self.TOR, whois={'count': 0, 'data': []}, port={'count': 0, 'data': []})
        summary = {'status': 200, 'country': 'United States', 'city': 'Fremont',
                   'isp': 'Akamai Connected Cloud', 'org_name': 'Akamai', 'as_no': 63949}
        with patch('requests.get', side_effect=[resp(200, report), resp(200, summary)]):
            r = CriminalIPClient().check_ip('45.33.32.156')
        assert r['country'] == 'United States'
        assert r['city'] == 'Fremont'
        assert r['isp'] == 'Akamai Connected Cloud'
        assert r['asn'] == 63949

    def test_summary_falla_no_rompe(self, app_ctx):
        from app.services.new_api_clients import CriminalIPClient
        report = dict(self.TOR, whois={'count': 0, 'data': []})
        with patch('requests.get', side_effect=[resp(200, report), Exception('boom')]):
            r = CriminalIPClient().check_ip('1.2.3.4')
        assert r['found'] is True and r['country'] is None


class TestCriminalIPDomainFlow:
    REPORT = {'status': 200, 'data': {
        'summary': {'abuse_record': {'critical': 0, 'dangerous': 0}, 'phishing_record': 0,
                    'fake_domain': False, 'dga_score': 0.0, 'newborn_domain': ''},
        'main_domain_info': {'domain_score': {'score': 'safe', 'score_num': 0.0},
                             'domain_created': '1995-08-14', 'domain_registrar': 'IANA'},
        'technologies': [{'name': 'Cloudflare'}], 'mapped_ip': [{'ip': '104.20.23.154'}]}}

    def _client(self):
        from app.services.new_api_clients import CriminalIPClient
        c = CriminalIPClient()
        c.DOMAIN_POLL_INTERVAL = 0
        return c

    def test_scan_status_report(self, app_ctx):
        scan = resp(200, {'status': 200, 'data': {'scan_id': 76986363}})
        gets = [resp(200, {'data': {'scan_percentage': 30}}),
                resp(200, {'data': {'scan_percentage': 100}}),
                resp(200, self.REPORT)]
        with patch('requests.post', return_value=scan) as post, patch('requests.get', side_effect=gets) as get:
            r = self._client().check_domain('example.com')
        assert post.call_args[0][0].endswith('/v1/domain/scan')
        assert post.call_args[1]['data'] == {'query': 'example.com'}
        assert get.call_args[0][0].endswith('/v2/domain/report/76986363')
        assert r['found'] is True and r['score'] == 'safe'
        assert r['is_malicious'] is False and r['is_phishing'] is False
        assert r['technologies'] == ['Cloudflare']

    def test_dominio_malicioso(self, app_ctx):
        rep = {'status': 200, 'data': {
            'summary': {'abuse_record': {'critical': 2, 'dangerous': 0}, 'phishing_record': 3},
            'main_domain_info': {'domain_score': {'score': 'critical'}}}}
        scan = resp(200, {'status': 200, 'data': {'scan_id': 1}})
        gets = [resp(200, {'data': {'scan_percentage': 100}}), resp(200, rep)]
        with patch('requests.post', return_value=scan), patch('requests.get', side_effect=gets):
            r = self._client().check_domain('evil.example')
        assert r['is_malicious'] is True and r['is_phishing'] is True

    def test_timeout_de_sondeo(self, app_ctx):
        c = self._client()
        c.DOMAIN_POLL_BUDGET = 0.05
        c.DOMAIN_POLL_INTERVAL = 0.01
        scan = resp(200, {'status': 200, 'data': {'scan_id': 9}})
        with patch('requests.post', return_value=scan), \
             patch('requests.get', return_value=resp(200, {'data': {'scan_percentage': 10}})):
            r = c.check_domain('slow.example')
        assert r['found'] is False and r['scan_id'] == 9 and 'error' not in r

    def test_scan_rechazado(self, app_ctx):
        with patch('requests.post', return_value=resp(200, {'status': 400, 'message': 'no credits'})):
            r = self._client().check_domain('x.example')
        assert r == {'error': 'no credits'}

    def test_rate_limit(self, app_ctx):
        with patch('requests.post', return_value=resp(429, {})):
            assert self._client().check_domain('x.example') == {'error': 'Rate limit excedido'}


class TestMalwareBazaarShape:
    def test_hash_real_encontrado(self, app_ctx):
        from app.services.new_api_clients import MalwareBazaarClient
        body = {'query_status': 'ok', 'data': [{
            'sha256_hash': '7a0f3b21', 'md5_hash': '66ac', 'file_type': 'sh', 'signature': None,
            'tags': ['sh'], 'intelligence': {'clamav': None, 'downloads': '18', 'uploads': '1'},
            'first_seen': '2026-11-13 23:38:04'}]}
        with patch('requests.post', return_value=resp(200, body)):
            r = MalwareBazaarClient().query_hash('7a0f3b21f69ef32dec83e199e1faee3188c0124a5454e60365f194564239e134')
        assert r['found'] is True and r['file_type'] == 'sh' and r['signature'] is None

    def test_hash_inexistente(self, app_ctx):
        from app.services.new_api_clients import MalwareBazaarClient
        with patch('requests.post', return_value=resp(200, {'query_status': 'hash_not_found'})):
            assert MalwareBazaarClient().query_hash('0' * 64)['found'] is False


class TestPulsediveThrottle:
    def test_espacia_llamadas(self):
        from app.services import new_api_clients as m
        m._pulsedive_last_call = 0.0
        with patch.object(m.time, 'sleep') as sl:
            m._pulsedive_throttle()      # primera: sin espera
            m._pulsedive_throttle()      # segunda inmediata: debe dormir
        assert sl.call_count == 1
        assert 0 < sl.call_args[0][0] <= m.PULSEDIVE_MIN_INTERVAL

    def test_slot_redis_espacia_entre_workers(self, app_ctx):
        """Con Redis, el slot (SET NX PX) decide; si ya está tomado, espera su pttl."""
        from app.services import new_api_clients as m
        fake = MagicMock()
        fake.set.side_effect = [False, True]       # 1er intento: slot ocupado; 2o: libre
        fake.pttl.return_value = 40
        with patch('redis.from_url', return_value=fake), patch.object(m.time, 'sleep') as sl:
            m._pulsedive_throttle()
        assert fake.set.call_count == 2
        sl.assert_called_once()
        assert fake.set.call_args[1]['nx'] is True
        assert fake.set.call_args[1]['px'] == int(m.PULSEDIVE_MIN_INTERVAL * 1000)

    def test_sin_redis_cae_a_espaciado_local(self, app_ctx):
        from app.services import new_api_clients as m
        m._pulsedive_last_call = 0.0
        with patch('redis.from_url', side_effect=Exception('down')), patch.object(m.time, 'sleep') as sl:
            m._pulsedive_throttle()
            m._pulsedive_throttle()
        assert sl.call_count == 1
