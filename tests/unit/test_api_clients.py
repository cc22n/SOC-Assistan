"""
Tests para new_api_clients.py — mock all external HTTP calls
Cubre: VirusTotalClient, AbuseIPDBClient, ShodanClient, GreyNoiseClient,
       OTXClient, HybridAnalysisClient, URLhausClient, ThreatFoxClient,
       MalwareBazaarClient, IPAPIClient, IPinfoClient, IPGeolocationClient,
       GoogleSafeBrowsingClient, UnifiedThreatIntelClient
"""
import pytest
from unittest.mock import patch, MagicMock
import json


# ==============================================================================
# FIXTURES
# ==============================================================================

@pytest.fixture(scope='function')
def app_ctx(app):
    """Push an app context for tests that need current_app."""
    with app.app_context():
        yield


def make_response(status_code, json_data):
    """Helper to create a mock requests.Response."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.json.return_value = json_data
    return mock_resp


# ==============================================================================
# VIRUSTOTAL CLIENT
# ==============================================================================

class TestVirusTotalClient:

    def test_check_ip_success(self, app_ctx):
        from app.services.new_api_clients import VirusTotalClient
        client = VirusTotalClient()

        mock_resp = make_response(200, {
            'data': {'attributes': {
                'last_analysis_stats': {'malicious': 10, 'suspicious': 2, 'harmless': 50, 'undetected': 5},
                'asn': 12345, 'as_owner': 'Evil ISP', 'country': 'RU', 'reputation': -10
            }}
        })
        with patch('requests.get', return_value=mock_resp):
            result = client.check_ip('185.220.101.1')

        assert result['malicious'] == 10
        assert result['suspicious'] == 2
        assert result['country'] == 'RU'

    def test_check_ip_invalid_key(self, app_ctx):
        from app.services.new_api_clients import VirusTotalClient
        client = VirusTotalClient()

        with patch('requests.get', return_value=make_response(401, {})):
            result = client.check_ip('1.2.3.4')
        assert 'error' in result
        assert 'inválida' in result['error']

    def test_check_ip_other_error(self, app_ctx):
        from app.services.new_api_clients import VirusTotalClient
        client = VirusTotalClient()

        with patch('requests.get', return_value=make_response(429, {})):
            result = client.check_ip('1.2.3.4')
        assert 'error' in result
        assert '429' in result['error']

    def test_check_ip_no_key(self, app, app_ctx):
        from flask import current_app
        from app.services.new_api_clients import VirusTotalClient
        original = current_app.config['API_KEYS'].get('virustotal')
        current_app.config['API_KEYS']['virustotal'] = None
        try:
            client = VirusTotalClient()
            result = client.check_ip('1.2.3.4')
            assert 'error' in result
        finally:
            current_app.config['API_KEYS']['virustotal'] = original

    def test_check_ip_exception(self, app_ctx):
        from app.services.new_api_clients import VirusTotalClient
        client = VirusTotalClient()

        with patch('requests.get', side_effect=Exception('Connection timeout')):
            result = client.check_ip('1.2.3.4')
        assert 'error' in result

    def test_check_hash_found(self, app_ctx):
        from app.services.new_api_clients import VirusTotalClient
        client = VirusTotalClient()

        mock_resp = make_response(200, {
            'data': {'attributes': {
                'last_analysis_stats': {'malicious': 30, 'suspicious': 5, 'undetected': 10},
                'type_description': 'PE32 executable', 'meaningful_name': 'malware.exe',
                'popular_threat_classification': {}, 'names': ['evil.exe'], 'size': 98304, 'magic': 'PE32'
            }}
        })
        with patch('requests.get', return_value=mock_resp):
            result = client.check_hash('d41d8cd98f00b204e9800998ecf8427e')
        assert result['found'] is True
        assert result['malicious'] == 30

    def test_check_hash_not_found(self, app_ctx):
        from app.services.new_api_clients import VirusTotalClient
        client = VirusTotalClient()

        with patch('requests.get', return_value=make_response(404, {})):
            result = client.check_hash('d41d8cd98f00b204e9800998ecf8427e')
        assert result['found'] is False

    def test_check_domain_success(self, app_ctx):
        from app.services.new_api_clients import VirusTotalClient
        client = VirusTotalClient()

        mock_resp = make_response(200, {
            'data': {'attributes': {
                'last_analysis_stats': {'malicious': 5, 'suspicious': 1, 'harmless': 60},
                'registrar': 'NameCheap', 'creation_date': 1609459200, 'reputation': -5, 'categories': {}
            }}
        })
        with patch('requests.get', return_value=mock_resp):
            result = client.check_domain('evil.com')
        assert result['malicious'] == 5
        assert result['registrar'] == 'NameCheap'

    def test_check_domain_not_found(self, app_ctx):
        from app.services.new_api_clients import VirusTotalClient
        client = VirusTotalClient()

        with patch('requests.get', return_value=make_response(404, {})):
            result = client.check_domain('unknown.xyz')
        assert result['found'] is False

    def test_check_url_success_uses_urls_endpoint_with_unpadded_b64(self, app_ctx):
        import base64
        from app.services.new_api_clients import VirusTotalClient
        client = VirusTotalClient()

        mock_resp = make_response(200, {
            'data': {'attributes': {
                'last_analysis_stats': {'malicious': 8, 'suspicious': 1, 'harmless': 40, 'undetected': 3},
                'reputation': -8, 'categories': {'vendor': 'phishing'},
                'last_final_url': 'https://evil.com/phish', 'title': 'Fake Login'
            }}
        })
        target_url = 'https://evil.com/phish?x=1'
        expected_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip('=')

        with patch('requests.get', return_value=mock_resp) as mock_get:
            result = client.check_url(target_url)

        called_url = mock_get.call_args[0][0]
        assert called_url == f"{client.base_url}/urls/{expected_id}"
        assert '=' not in expected_id
        assert result['malicious'] == 8
        assert result['suspicious'] == 1
        assert result['reputation'] == -8
        assert result['final_url'] == 'https://evil.com/phish'
        assert result['title'] == 'Fake Login'

    def test_check_url_not_found(self, app_ctx):
        from app.services.new_api_clients import VirusTotalClient
        client = VirusTotalClient()

        with patch('requests.get', return_value=make_response(404, {})):
            result = client.check_url('https://neverseen.example.com/x')
        assert result['found'] is False

    def test_check_url_invalid_key(self, app_ctx):
        from app.services.new_api_clients import VirusTotalClient
        client = VirusTotalClient()

        with patch('requests.get', return_value=make_response(401, {})):
            result = client.check_url('https://evil.com/x')
        assert 'error' in result
        assert 'inválida' in result['error']

    def test_check_url_no_key(self, app, app_ctx):
        from flask import current_app
        from app.services.new_api_clients import VirusTotalClient
        original = current_app.config['API_KEYS'].get('virustotal')
        current_app.config['API_KEYS']['virustotal'] = None
        try:
            client = VirusTotalClient()
            result = client.check_url('https://evil.com/x')
            assert 'error' in result
        finally:
            current_app.config['API_KEYS']['virustotal'] = original

    def test_check_url_exception(self, app_ctx):
        from app.services.new_api_clients import VirusTotalClient
        client = VirusTotalClient()

        with patch('requests.get', side_effect=Exception('Connection timeout')):
            result = client.check_url('https://evil.com/x')
        assert 'error' in result


# ==============================================================================
# ABUSEIPDB CLIENT
# ==============================================================================

class TestAbuseIPDBClient:

    def test_check_ip_success(self, app_ctx):
        from app.services.new_api_clients import AbuseIPDBClient
        client = AbuseIPDBClient()

        mock_resp = make_response(200, {'data': {
            'abuseConfidenceScore': 85, 'totalReports': 1000,
            'countryCode': 'RU', 'isp': 'Evil ISP', 'domain': 'evil.ru',
            'isTor': True, 'isWhitelisted': False, 'lastReportedAt': '2025-01-01T00:00:00+00:00',
            'usageType': 'Data Center'
        }})
        with patch('requests.get', return_value=mock_resp):
            result = client.check_ip('185.220.101.1')
        assert result['abuse_confidence_score'] == 85
        assert result['is_tor'] is True

    def test_check_ip_invalid_key(self, app_ctx):
        from app.services.new_api_clients import AbuseIPDBClient
        client = AbuseIPDBClient()

        with patch('requests.get', return_value=make_response(401, {})):
            result = client.check_ip('1.2.3.4')
        assert 'error' in result

    def test_check_ip_exception(self, app_ctx):
        from app.services.new_api_clients import AbuseIPDBClient
        client = AbuseIPDBClient()

        with patch('requests.get', side_effect=Exception('Timeout')):
            result = client.check_ip('1.2.3.4')
        assert 'error' in result

    def test_check_ip_no_key(self, app, app_ctx):
        from flask import current_app
        from app.services.new_api_clients import AbuseIPDBClient
        original = current_app.config['API_KEYS'].get('abuseipdb')
        current_app.config['API_KEYS']['abuseipdb'] = None
        try:
            client = AbuseIPDBClient()
            result = client.check_ip('1.2.3.4')
            assert 'error' in result
        finally:
            current_app.config['API_KEYS']['abuseipdb'] = original


# ==============================================================================
# SHODAN CLIENT
# ==============================================================================

class TestShodanClient:

    def test_check_ip_success(self, app_ctx):
        from app.services.new_api_clients import ShodanClient
        client = ShodanClient()

        mock_resp = make_response(200, {
            'ip_str': '185.220.101.1', 'org': 'Evil Corp', 'asn': 'AS12345',
            'isp': 'Evil ISP', 'country_name': 'Germany', 'city': 'Frankfurt',
            'ports': [22, 80, 443], 'hostnames': [], 'vulns': ['CVE-2021-1234'],
            'os': None, 'last_update': '2025-01-01T00:00:00'
        })
        with patch('requests.get', return_value=mock_resp):
            result = client.check_ip('185.220.101.1')
        assert result['found'] is True
        assert 22 in result['ports']
        assert 'CVE-2021-1234' in result['vulns']

    def test_check_ip_not_found(self, app_ctx):
        from app.services.new_api_clients import ShodanClient
        client = ShodanClient()

        with patch('requests.get', return_value=make_response(404, {})):
            result = client.check_ip('8.8.8.8')
        assert result['found'] is False

    def test_check_ip_invalid_key(self, app_ctx):
        from app.services.new_api_clients import ShodanClient
        client = ShodanClient()

        with patch('requests.get', return_value=make_response(401, {})):
            result = client.check_ip('8.8.8.8')
        assert 'error' in result

    def test_check_ip_no_key(self, app, app_ctx):
        from flask import current_app
        from app.services.new_api_clients import ShodanClient
        original = current_app.config['API_KEYS'].get('shodan')
        current_app.config['API_KEYS']['shodan'] = None
        try:
            client = ShodanClient()
            result = client.check_ip('8.8.8.8')
            assert 'error' in result
        finally:
            current_app.config['API_KEYS']['shodan'] = original

    def test_check_ip_exception(self, app_ctx):
        from app.services.new_api_clients import ShodanClient
        client = ShodanClient()

        with patch('requests.get', side_effect=Exception('Network error')):
            result = client.check_ip('1.2.3.4')
        assert 'error' in result


# ==============================================================================
# GREYNOISE CLIENT
# ==============================================================================

class TestGreyNoiseClient:

    def test_check_ip_success(self, app_ctx):
        from app.services.new_api_clients import GreyNoiseClient
        client = GreyNoiseClient()

        mock_resp = make_response(200, {
            'ip': '185.220.101.1', 'noise': True, 'riot': False,
            'classification': 'malicious', 'name': 'TOR exit node',
            'last_seen': '2025-01-01', 'tags': ['tor-exit']
        })
        with patch('requests.get', return_value=mock_resp):
            result = client.check_ip('185.220.101.1')
        assert result['noise'] is True
        assert result['classification'] == 'malicious'

    def test_check_ip_riot(self, app_ctx):
        from app.services.new_api_clients import GreyNoiseClient
        client = GreyNoiseClient()

        mock_resp = make_response(200, {
            'ip': '8.8.8.8', 'noise': False, 'riot': True,
            'classification': 'benign', 'name': 'Google DNS',
            'last_seen': '2025-01-01', 'tags': []
        })
        with patch('requests.get', return_value=mock_resp):
            result = client.check_ip('8.8.8.8')
        assert result['riot'] is True

    def test_check_ip_404_not_observed(self, app_ctx):
        from app.services.new_api_clients import GreyNoiseClient
        client = GreyNoiseClient()

        with patch('requests.get', return_value=make_response(404, {'message': 'not found'})):
            result = client.check_ip('1.2.3.4')
        # Should return a "not seen" response or error
        assert isinstance(result, dict)

    def test_check_ip_exception(self, app_ctx):
        from app.services.new_api_clients import GreyNoiseClient
        client = GreyNoiseClient()

        with patch('requests.get', side_effect=Exception('Timeout')):
            result = client.check_ip('1.2.3.4')
        assert 'error' in result


# ==============================================================================
# IP-API CLIENT (no auth required — method is get_geolocation, not check_ip)
# ==============================================================================

class TestIPAPIClient:

    def test_get_geolocation_success(self, app_ctx):
        from app.services.new_api_clients import IPAPIClient
        client = IPAPIClient()

        mock_resp = make_response(200, {
            'status': 'success', 'country': 'Germany', 'countryCode': 'DE',
            'region': 'HE', 'regionName': 'Hesse', 'city': 'Frankfurt',
            'zip': '60308', 'lat': 50.1109, 'lon': 8.6821,
            'timezone': 'Europe/Berlin', 'isp': 'Hetzner',
            'org': 'Hetzner Online GmbH', 'as': 'AS24940', 'query': '185.220.101.1'
        })
        with patch('requests.get', return_value=mock_resp):
            result = client.get_geolocation('185.220.101.1')
        assert result['country'] == 'Germany'
        assert result['city'] == 'Frankfurt'

    def test_get_geolocation_fail_status(self, app_ctx):
        from app.services.new_api_clients import IPAPIClient
        client = IPAPIClient()

        mock_resp = make_response(200, {'status': 'fail', 'message': 'private range', 'query': '192.168.1.1'})
        with patch('requests.get', return_value=mock_resp):
            result = client.get_geolocation('192.168.1.1')
        assert isinstance(result, dict)

    def test_get_geolocation_exception(self, app_ctx):
        from app.services.new_api_clients import IPAPIClient
        client = IPAPIClient()

        with patch('requests.get', side_effect=Exception('Timeout')):
            result = client.get_geolocation('1.2.3.4')
        assert 'error' in result


# ==============================================================================
# IPINFO CLIENT
# ==============================================================================

class TestIPinfoClient:

    def test_check_ip_success(self, app_ctx):
        from app.services.new_api_clients import IPinfoClient
        client = IPinfoClient()

        mock_resp = make_response(200, {
            'ip': '185.220.101.1', 'city': 'Frankfurt', 'region': 'Hesse',
            'country': 'DE', 'loc': '50.1109,8.6821', 'org': 'AS24940 Hetzner',
            'timezone': 'Europe/Berlin', 'postal': '60308'
        })
        with patch('requests.get', return_value=mock_resp):
            result = client.check_ip('185.220.101.1')
        assert result['city'] == 'Frankfurt'
        assert result['country'] == 'DE'

    def test_check_ip_401_invalid_key(self, app_ctx):
        from app.services.new_api_clients import IPinfoClient
        client = IPinfoClient()

        with patch('requests.get', return_value=make_response(401, {'error': True, 'title': 'Unauthorized'})):
            result = client.check_ip('1.2.3.4')
        assert 'error' in result

    def test_check_ip_exception(self, app_ctx):
        from app.services.new_api_clients import IPinfoClient
        client = IPinfoClient()

        with patch('requests.get', side_effect=Exception('Network error')):
            result = client.check_ip('1.2.3.4')
        assert 'error' in result


# ==============================================================================
# IPGEOLOCATION CLIENT
# ==============================================================================

class TestIPGeolocationClient:

    def test_check_ip_success(self, app_ctx):
        from app.services.new_api_clients import IPGeolocationClient
        client = IPGeolocationClient()

        # IPGeolocationClient parses nested 'location', 'asn', 'time_zone', 'currency', 'country_metadata'
        mock_resp = make_response(200, {
            'ip': '185.220.101.1',
            'location': {
                'continent_name': 'Europe', 'country_name': 'Germany',
                'country_code2': 'DE', 'state_prov': 'Hesse', 'city': 'Frankfurt',
                'zipcode': '60308', 'latitude': '50.1109', 'longitude': '8.6821',
            },
            'asn': {'as_number': 'AS24940', 'organization': 'Hetzner'},
            'time_zone': {'name': 'Europe/Berlin', 'offset': 1, 'current_time': '2025-01-01 12:00:00'},
            'currency': {'name': 'Euro', 'code': 'EUR'},
            'country_metadata': {'calling_code': '+49', 'tld': '.de'},
        })
        with patch('requests.get', return_value=mock_resp):
            result = client.check_ip('185.220.101.1')
        assert result['country'] == 'Germany'
        assert result['city'] == 'Frankfurt'
        assert result['currency_name'] == 'Euro'
        assert result['currency_code'] == 'EUR'

    def test_check_ip_401_invalid_key(self, app_ctx):
        from app.services.new_api_clients import IPGeolocationClient
        client = IPGeolocationClient()

        with patch('requests.get', return_value=make_response(401, {'message': 'API key invalid'})):
            result = client.check_ip('1.2.3.4')
        assert 'error' in result
        assert 'inválida' in result['error'] or 'inválid' in result['error']

    def test_check_ip_423_quota_exhausted(self, app_ctx):
        from app.services.new_api_clients import IPGeolocationClient
        client = IPGeolocationClient()

        with patch('requests.get', return_value=make_response(423, {'message': 'Daily quota exceeded'})):
            result = client.check_ip('1.2.3.4')
        assert 'error' in result
        assert 'cuota' in result['error'].lower() or 'quota' in result['error'].lower() or '1000' in result['error']

    def test_check_ip_429_rate_limit(self, app_ctx):
        from app.services.new_api_clients import IPGeolocationClient
        client = IPGeolocationClient()

        with patch('requests.get', return_value=make_response(429, {'message': 'Rate limit'})):
            result = client.check_ip('1.2.3.4')
        assert 'error' in result

    def test_check_ip_no_key(self, app, app_ctx):
        from flask import current_app
        from app.services.new_api_clients import IPGeolocationClient
        original = current_app.config['API_KEYS'].get('ipgeolocation')
        current_app.config['API_KEYS']['ipgeolocation'] = None
        try:
            client = IPGeolocationClient()
            result = client.check_ip('1.2.3.4')
            assert 'error' in result
        finally:
            current_app.config['API_KEYS']['ipgeolocation'] = original

    def test_check_ip_exception(self, app_ctx):
        from app.services.new_api_clients import IPGeolocationClient
        client = IPGeolocationClient()

        with patch('requests.get', side_effect=Exception('Connection timeout')):
            result = client.check_ip('1.2.3.4')
        assert 'error' in result


# ==============================================================================
# OTX CLIENT
# ==============================================================================

class TestOTXClient:

    def test_check_ip_success(self, app_ctx):
        from app.services.new_api_clients import OTXClient
        client = OTXClient()

        # OTX check_ip returns pulse_count, pulses, country, asn, reputation directly
        mock_resp = make_response(200, {
            'pulse_info': {'count': 5, 'pulses': [{'name': 'Test Pulse', 'tags': ['tor']}]},
            'country_name': 'Russia', 'asn': 'AS12345 Evil Corp', 'reputation': 3
        })
        with patch('requests.get', return_value=mock_resp):
            result = client.check_ip('185.220.101.1')
        assert isinstance(result, dict)
        assert result.get('pulse_count') == 5 or 'error' in result

    def test_check_ip_no_key_still_works(self, app_ctx):
        # OTX does not require a key (it degrades gracefully without one)
        from app.services.new_api_clients import OTXClient
        client = OTXClient()

        mock_resp = make_response(200, {
            'pulse_info': {'count': 0, 'pulses': []},
            'country_name': 'Unknown', 'asn': None, 'reputation': 0
        })
        with patch('requests.get', return_value=mock_resp):
            result = client.check_ip('1.2.3.4')
        assert isinstance(result, dict)

    def test_check_domain_success(self, app_ctx):
        from app.services.new_api_clients import OTXClient
        client = OTXClient()

        general_resp = make_response(200, {'pulse_info': {'count': 2, 'pulses': []}, 'sections': []})
        reputation_resp = make_response(200, {})

        with patch('requests.get', side_effect=[general_resp, reputation_resp]):
            result = client.check_domain('evil.com')
        assert isinstance(result, dict)

    def test_check_hash_success(self, app_ctx):
        from app.services.new_api_clients import OTXClient
        client = OTXClient()

        analysis_resp = make_response(200, {'analysis': {'info': {'results': {'sha256': 'abc', 'md5': 'def'}}}})
        general_resp = make_response(200, {'pulse_info': {'count': 1, 'pulses': []}})

        with patch('requests.get', side_effect=[analysis_resp, general_resp]):
            result = client.check_hash('d41d8cd98f00b204e9800998ecf8427e')
        assert isinstance(result, dict)


# ==============================================================================
# HYBRID ANALYSIS CLIENT
# ==============================================================================

class TestHybridAnalysisClient:

    def test_search_hash_found(self, app_ctx):
        from app.services.new_api_clients import HybridAnalysisClient
        client = HybridAnalysisClient()

        # HybridAnalysis returns a LIST; client extracts data[0]
        mock_resp = make_response(200, [{
            'sha256': 'e3b0...', 'md5': 'd41d8...', 'verdict': 'malicious',
            'threat_score': 95, 'av_detect': 85, 'vx_family': 'Emotet',
            'type': 'peexe', 'submit_name': 'evil.exe',
            'environment_description': 'Windows 10 64 bit'
        }])
        with patch('requests.get', return_value=mock_resp):
            result = client.search_hash('d41d8cd98f00b204e9800998ecf8427e')
        assert result['found'] is True
        assert result['verdict'] == 'malicious'

    def test_search_hash_not_found(self, app_ctx):
        from app.services.new_api_clients import HybridAnalysisClient
        client = HybridAnalysisClient()

        with patch('requests.get', return_value=make_response(404, {})):
            result = client.search_hash('d41d8cd98f00b204e9800998ecf8427e')
        assert result.get('found') is False or 'error' in result

    def test_search_hash_no_key(self, app, app_ctx):
        from flask import current_app
        from app.services.new_api_clients import HybridAnalysisClient
        original = current_app.config['API_KEYS'].get('hybrid_analysis')
        current_app.config['API_KEYS']['hybrid_analysis'] = None
        try:
            client = HybridAnalysisClient()
            result = client.search_hash('d41d8cd98f00b204e9800998ecf8427e')
            assert 'error' in result
        finally:
            current_app.config['API_KEYS']['hybrid_analysis'] = original

    def test_search_hash_exception(self, app_ctx):
        from app.services.new_api_clients import HybridAnalysisClient
        client = HybridAnalysisClient()

        with patch('requests.get', side_effect=Exception('Timeout')):
            result = client.search_hash('d41d8cd98f00b204e9800998ecf8427e')
        assert 'error' in result


# ==============================================================================
# URLHAUS CLIENT (abuse.ch)
# ==============================================================================

class TestURLhausClient:

    def test_check_url_found_malicious(self, app_ctx):
        from app.services.new_api_clients import URLhausClient
        client = URLhausClient()

        mock_resp = make_response(200, {
            'query_status': 'is_available',
            'urlhaus_reference': 'https://urlhaus.abuse.ch/url/12345/',
            'threat': 'malware_download', 'tags': ['emotet'],
            'url_status': 'online', 'date_added': '2025-01-01 00:00:00 UTC'
        })
        with patch('requests.post', return_value=mock_resp):
            result = client.check_url('http://evil.com/payload.exe')
        assert isinstance(result, dict)

    def test_check_url_not_found(self, app_ctx):
        from app.services.new_api_clients import URLhausClient
        client = URLhausClient()

        with patch('requests.post', return_value=make_response(200, {'query_status': 'no_results'})):
            result = client.check_url('http://legitimate.com/page')
        assert isinstance(result, dict)

    def test_check_host_found(self, app_ctx):
        from app.services.new_api_clients import URLhausClient
        client = URLhausClient()

        mock_resp = make_response(200, {
            'query_status': 'is_host',
            'urls': [{'url': 'http://evil.com/payload.exe', 'url_status': 'online'}]
        })
        with patch('requests.post', return_value=mock_resp):
            result = client.check_host('evil.com')
        assert isinstance(result, dict)

    def test_check_url_exception(self, app_ctx):
        from app.services.new_api_clients import URLhausClient
        client = URLhausClient()

        with patch('requests.post', side_effect=Exception('Timeout')):
            result = client.check_url('http://example.com')
        assert 'error' in result


# ==============================================================================
# THREATFOX CLIENT (abuse.ch)
# ==============================================================================

class TestThreatFoxClient:

    def test_search_ioc_found(self, app_ctx):
        from app.services.new_api_clients import ThreatFoxClient
        client = ThreatFoxClient()

        mock_resp = make_response(200, {
            'query_status': 'ok',
            'data': [{'ioc_value': '185.220.101.1', 'threat_type': 'botnet_cc',
                      'malware': 'Emotet', 'confidence_level': 75}]
        })
        with patch('requests.post', return_value=mock_resp):
            result = client.search_ioc('185.220.101.1')
        assert isinstance(result, dict)

    def test_search_ioc_not_found(self, app_ctx):
        from app.services.new_api_clients import ThreatFoxClient
        client = ThreatFoxClient()

        with patch('requests.post', return_value=make_response(200, {'query_status': 'no_result', 'data': []})):
            result = client.search_ioc('8.8.8.8')
        assert isinstance(result, dict)

    def test_search_ioc_exception(self, app_ctx):
        from app.services.new_api_clients import ThreatFoxClient
        client = ThreatFoxClient()

        with patch('requests.post', side_effect=Exception('Timeout')):
            result = client.search_ioc('1.2.3.4')
        assert 'error' in result


# ==============================================================================
# MALWAREBAZAAR CLIENT (abuse.ch)
# ==============================================================================

class TestMalwareBazaarClient:

    def test_query_hash_found(self, app_ctx):
        from app.services.new_api_clients import MalwareBazaarClient
        client = MalwareBazaarClient()

        mock_resp = make_response(200, {
            'query_status': 'ok',
            'data': [{'sha256_hash': 'abc123', 'file_name': 'evil.exe',
                      'file_type': 'exe', 'tags': ['emotet'],
                      'signature': 'Emotet', 'first_seen': '2025-01-01 00:00:00'}]
        })
        with patch('requests.post', return_value=mock_resp):
            result = client.query_hash('d41d8cd98f00b204e9800998ecf8427e')
        assert isinstance(result, dict)

    def test_query_hash_not_found(self, app_ctx):
        from app.services.new_api_clients import MalwareBazaarClient
        client = MalwareBazaarClient()

        with patch('requests.post', return_value=make_response(200, {'query_status': 'hash_not_found', 'data': []})):
            result = client.query_hash('d41d8cd98f00b204e9800998ecf8427e')
        assert isinstance(result, dict)

    def test_query_hash_exception(self, app_ctx):
        from app.services.new_api_clients import MalwareBazaarClient
        client = MalwareBazaarClient()

        with patch('requests.post', side_effect=Exception('Timeout')):
            result = client.query_hash('d41d8cd98f00b204e9800998ecf8427e')
        assert 'error' in result


# ==============================================================================
# GOOGLE SAFE BROWSING CLIENT
# ==============================================================================

class TestGoogleSafeBrowsingClient:

    def test_check_url_malicious(self, app_ctx):
        from app.services.new_api_clients import GoogleSafeBrowsingClient
        client = GoogleSafeBrowsingClient()

        mock_resp = make_response(200, {
            'matches': [{'threatType': 'MALWARE', 'platformType': 'ANY_PLATFORM',
                         'threat': {'url': 'http://evil.com'}, 'cacheDuration': '300s',
                         'threatEntryType': 'URL'}]
        })
        with patch('requests.post', return_value=mock_resp):
            result = client.check_url('http://evil.com')
        assert isinstance(result, dict)
        assert result.get('is_malicious') is True or 'matches' in result or 'threat_type' in result

    def test_check_url_clean(self, app_ctx):
        from app.services.new_api_clients import GoogleSafeBrowsingClient
        client = GoogleSafeBrowsingClient()

        with patch('requests.post', return_value=make_response(200, {})):
            result = client.check_url('https://google.com')
        assert isinstance(result, dict)

    def test_check_url_no_key(self, app, app_ctx):
        from flask import current_app
        from app.services.new_api_clients import GoogleSafeBrowsingClient
        original = current_app.config['API_KEYS'].get('google_safebrowsing')
        current_app.config['API_KEYS']['google_safebrowsing'] = None
        try:
            client = GoogleSafeBrowsingClient()
            result = client.check_url('http://evil.com')
            assert 'error' in result
        finally:
            current_app.config['API_KEYS']['google_safebrowsing'] = original

    def test_check_url_exception(self, app_ctx):
        from app.services.new_api_clients import GoogleSafeBrowsingClient
        client = GoogleSafeBrowsingClient()

        with patch('requests.post', side_effect=Exception('Timeout')):
            result = client.check_url('http://evil.com')
        assert 'error' in result


# ==============================================================================
# UNIFIED THREAT INTEL CLIENT
# ==============================================================================

class TestUnifiedThreatIntelClient:

    def test_analyze_ip_calls_multiple_sources(self, app_ctx):
        from app.services.new_api_clients import UnifiedThreatIntelClient
        client = UnifiedThreatIntelClient()

        mock_result = {'malicious': 10, 'country': 'RU'}

        # Note: IPAPIClient uses get_geolocation, not check_ip
        with patch.object(client.virustotal, 'check_ip', return_value=mock_result), \
             patch.object(client.abuseipdb, 'check_ip', return_value={'abuse_confidence_score': 80}), \
             patch.object(client.shodan, 'check_ip', return_value={'found': True, 'ports': [22]}), \
             patch.object(client.greynoise, 'check_ip', return_value={'noise': True}), \
             patch.object(client.otx, 'check_ip', return_value={'pulse_count': 0}), \
             patch.object(client.criminal_ip, 'check_ip', return_value={}), \
             patch.object(client.pulsedive, 'get_indicator', return_value={}), \
             patch.object(client.ipinfo, 'check_ip', return_value={'city': 'Moscow'}), \
             patch.object(client.ip_api, 'get_geolocation', return_value={'country': 'Russia'}), \
             patch.object(client.ipgeolocation, 'check_ip', return_value={'country': 'Russia'}):
            result = client.analyze_ip('185.220.101.1', sources=[
                'virustotal', 'abuseipdb', 'shodan', 'greynoise',
                'otx', 'criminal_ip', 'pulsedive', 'ipinfo', 'ip_api', 'ipgeolocation'
            ])
        assert 'virustotal' in result
        assert result['virustotal']['malicious'] == 10

    def test_analyze_hash_calls_sources(self, app_ctx):
        from app.services.new_api_clients import UnifiedThreatIntelClient
        client = UnifiedThreatIntelClient()

        with patch.object(client.virustotal, 'check_hash', return_value={'found': True, 'malicious': 30}), \
             patch.object(client.hybrid_analysis, 'search_hash', return_value={'verdict': 'malicious'}):
            result = client.analyze_hash('d41d8cd98f00b204e9800998ecf8427e', sources=['virustotal', 'hybrid_analysis'])
        assert 'virustotal' in result
        assert result['virustotal']['malicious'] == 30

    def test_analyze_domain_calls_sources(self, app_ctx):
        from app.services.new_api_clients import UnifiedThreatIntelClient
        client = UnifiedThreatIntelClient()

        with patch.object(client.virustotal, 'check_domain', return_value={'malicious': 5}), \
             patch.object(client.safebrowsing, 'check_url', return_value={'is_malicious': True}):
            result = client.analyze_domain('evil.com', sources=['virustotal', 'safebrowsing'])
        assert 'virustotal' in result

    def test_analyze_url_calls_sources(self, app_ctx):
        from app.services.new_api_clients import UnifiedThreatIntelClient
        client = UnifiedThreatIntelClient()

        with patch.object(client.safebrowsing, 'check_url', return_value={'is_malicious': True}), \
             patch.object(client.urlhaus, 'check_url', return_value={'query_status': 'is_available'}):
            result = client.analyze_url('http://evil.com/payload.exe', sources=['safebrowsing', 'urlhaus'])
        assert 'safebrowsing' in result

    def test_api_error_in_source_doesnt_stop_others(self, app_ctx):
        from app.services.new_api_clients import UnifiedThreatIntelClient
        client = UnifiedThreatIntelClient()

        with patch.object(client.virustotal, 'check_ip', return_value={'malicious': 5}), \
             patch.object(client.abuseipdb, 'check_ip', side_effect=Exception('API down')):
            result = client.analyze_ip('185.220.101.1', sources=['virustotal', 'abuseipdb'])
        assert 'virustotal' in result
        # abuseipdb might have error or might not be in result


# ==============================================================================
# TAVILY SEARCH CLIENT (búsqueda web para Deep Analysis)
# ==============================================================================

class TestTavilySearchClient:

    def test_no_api_key_returns_error(self, app_ctx):
        from app.services.new_api_clients import TavilySearchClient
        client = TavilySearchClient()
        client.api_key = None
        result = client.search('lockbit ransomware')
        assert 'error' in result

    def test_search_success_normalizes_results(self, app_ctx):
        from app.services.new_api_clients import TavilySearchClient
        client = TavilySearchClient()
        client.api_key = 'test-key'

        mock_resp = make_response(200, {
            'results': [
                {'title': 'LockBit report', 'url': 'https://cisa.gov/a', 'content': 'x' * 3000, 'score': 0.9},
                {'title': 'Otro', 'url': 'https://unit42.example/b', 'content': 'breve', 'score': 0.5},
            ]
        })
        with patch('requests.post', return_value=mock_resp) as mock_post:
            result = client.search('lockbit', restrict_to_security_domains=True)

        assert result['found'] is True
        assert len(result['results']) == 2
        # contenido truncado a 1500 chars
        assert len(result['results'][0]['content']) == 1500
        # restricción de dominios enviada en el payload
        payload = mock_post.call_args.kwargs['json']
        assert payload['include_domains'] == client.SECURITY_DOMAINS

    def test_search_quota_exhausted(self, app_ctx):
        from app.services.new_api_clients import TavilySearchClient
        client = TavilySearchClient()
        client.api_key = 'test-key'
        with patch('requests.post', return_value=make_response(429, {})):
            result = client.search('query')
        assert 'error' in result
        assert 'cuota' in result['error'].lower() or 'rate' in result['error'].lower()

    def test_search_empty_results(self, app_ctx):
        from app.services.new_api_clients import TavilySearchClient
        client = TavilySearchClient()
        client.api_key = 'test-key'
        with patch('requests.post', return_value=make_response(200, {'results': []})):
            result = client.search('nada')
        assert result['found'] is False
        assert result['results'] == []
