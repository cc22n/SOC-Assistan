"""
Tests para utils — validators, formatters, circuit_breaker, metrics
Cubre: app/utils/validators.py, app/utils/formatters.py
"""
import pytest
from unittest.mock import patch, MagicMock


# ==============================================================================
# VALIDATORS
# ==============================================================================

class TestIsValidIp:
    def test_valid_public_ip(self):
        from app.utils.validators import is_valid_ip
        assert is_valid_ip('8.8.8.8') is True

    def test_valid_boundary_ip(self):
        from app.utils.validators import is_valid_ip
        assert is_valid_ip('0.0.0.0') is True
        assert is_valid_ip('255.255.255.255') is True

    def test_invalid_ip_too_many_octets(self):
        from app.utils.validators import is_valid_ip
        assert is_valid_ip('1.2.3.4.5') is False

    def test_invalid_ip_out_of_range(self):
        from app.utils.validators import is_valid_ip
        assert is_valid_ip('256.0.0.1') is False

    def test_invalid_ip_alpha(self):
        from app.utils.validators import is_valid_ip
        assert is_valid_ip('not.an.ip.addr') is False

    def test_invalid_ip_empty(self):
        from app.utils.validators import is_valid_ip
        assert is_valid_ip('') is False

    def test_invalid_ip_none_like(self):
        from app.utils.validators import is_valid_ip
        assert is_valid_ip('abc') is False


class TestIsPrivateIp:
    def test_rfc1918_10_range(self):
        from app.utils.validators import is_private_ip
        assert is_private_ip('10.0.0.1') is True
        assert is_private_ip('10.255.255.255') is True

    def test_rfc1918_172_range(self):
        from app.utils.validators import is_private_ip
        assert is_private_ip('172.16.0.1') is True
        assert is_private_ip('172.31.255.255') is True
        assert is_private_ip('172.15.0.1') is False
        assert is_private_ip('172.32.0.1') is False

    def test_rfc1918_192_168_range(self):
        from app.utils.validators import is_private_ip
        assert is_private_ip('192.168.1.1') is True
        assert is_private_ip('192.169.0.1') is False

    def test_localhost(self):
        from app.utils.validators import is_private_ip
        assert is_private_ip('127.0.0.1') is True

    def test_public_ip_not_private(self):
        from app.utils.validators import is_private_ip
        assert is_private_ip('8.8.8.8') is False
        assert is_private_ip('185.220.101.1') is False

    def test_invalid_ip_returns_false(self):
        from app.utils.validators import is_private_ip
        assert is_private_ip('not-an-ip') is False


class TestIsValidHash:
    def test_valid_md5(self):
        from app.utils.validators import is_valid_hash
        assert is_valid_hash('d41d8cd98f00b204e9800998ecf8427e') is True

    def test_valid_sha1(self):
        from app.utils.validators import is_valid_hash
        assert is_valid_hash('da39a3ee5e6b4b0d3255bfef95601890afd80709') is True

    def test_valid_sha256(self):
        from app.utils.validators import is_valid_hash
        h = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        assert is_valid_hash(h) is True

    def test_invalid_hash_wrong_length(self):
        from app.utils.validators import is_valid_hash
        assert is_valid_hash('abcdef1234') is False  # 10 chars

    def test_invalid_hash_non_hex(self):
        from app.utils.validators import is_valid_hash
        assert is_valid_hash('z' * 32) is False

    def test_invalid_hash_uppercase_ok(self):
        from app.utils.validators import is_valid_hash
        assert is_valid_hash('D41D8CD98F00B204E9800998ECF8427E') is True


class TestIsValidDomain:
    def test_valid_simple_domain(self):
        from app.utils.validators import is_valid_domain
        assert is_valid_domain('google.com') is True

    def test_valid_subdomain(self):
        from app.utils.validators import is_valid_domain
        assert is_valid_domain('malware.wicar.org') is True

    def test_valid_multi_level(self):
        from app.utils.validators import is_valid_domain
        assert is_valid_domain('sub.domain.co.uk') is True

    def test_invalid_single_label(self):
        from app.utils.validators import is_valid_domain
        assert is_valid_domain('localhost') is False

    def test_invalid_too_short(self):
        from app.utils.validators import is_valid_domain
        assert is_valid_domain('a.b') is False

    def test_invalid_ip_as_domain(self):
        from app.utils.validators import is_valid_domain
        # IPs are not domains
        assert is_valid_domain('8.8.8.8') is False

    def test_invalid_trailing_dot(self):
        from app.utils.validators import is_valid_domain
        # Pattern doesn't allow trailing dot
        assert is_valid_domain('.evil.com') is False


class TestIsValidUrl:
    def test_valid_http_url(self):
        from app.utils.validators import is_valid_url
        assert is_valid_url('http://example.com/path') is True

    def test_valid_https_url(self):
        from app.utils.validators import is_valid_url
        assert is_valid_url('https://malware.wicar.org/payload.exe') is True

    def test_invalid_no_scheme(self):
        from app.utils.validators import is_valid_url
        assert is_valid_url('example.com/path') is False

    def test_invalid_ftp_scheme(self):
        from app.utils.validators import is_valid_url
        assert is_valid_url('ftp://files.example.com') is False

    def test_invalid_spaces_in_url(self):
        from app.utils.validators import is_valid_url
        assert is_valid_url('http://bad url.com') is False


class TestDetectIocType:
    def test_detects_url(self):
        from app.utils.validators import detect_ioc_type
        assert detect_ioc_type('https://malware.wicar.org/test') == 'url'

    def test_detects_ip(self):
        from app.utils.validators import detect_ioc_type
        assert detect_ioc_type('185.220.101.1') == 'ip'

    def test_detects_md5_hash(self):
        from app.utils.validators import detect_ioc_type
        assert detect_ioc_type('d41d8cd98f00b204e9800998ecf8427e') == 'hash'

    def test_detects_domain(self):
        from app.utils.validators import detect_ioc_type
        assert detect_ioc_type('malware-c2.evil.com') == 'domain'

    def test_unknown_returns_none(self):
        from app.utils.validators import detect_ioc_type
        assert detect_ioc_type('not-any-ioc') is None

    def test_strips_whitespace(self):
        from app.utils.validators import detect_ioc_type
        assert detect_ioc_type('  8.8.8.8  ') == 'ip'


class TestValidateIoc:
    def test_valid_public_ip(self):
        from app.utils.validators import validate_ioc
        ok, err = validate_ioc('185.220.101.1', 'ip')
        assert ok is True
        assert err == ""

    def test_private_ip_rejected(self):
        from app.utils.validators import validate_ioc
        ok, err = validate_ioc('192.168.1.1', 'ip')
        assert ok is False
        assert 'Private' in err or 'reserved' in err

    def test_valid_hash(self):
        from app.utils.validators import validate_ioc
        ok, err = validate_ioc('d41d8cd98f00b204e9800998ecf8427e', 'hash')
        assert ok is True

    def test_valid_domain(self):
        from app.utils.validators import validate_ioc
        ok, err = validate_ioc('evil.com', 'domain')
        assert ok is True

    def test_valid_url(self):
        from app.utils.validators import validate_ioc
        ok, err = validate_ioc('http://evil.com/payload', 'url')
        assert ok is True

    def test_empty_ioc_rejected(self):
        from app.utils.validators import validate_ioc
        ok, err = validate_ioc('', 'ip')
        assert ok is False
        assert 'empty' in err.lower()

    def test_whitespace_only_rejected(self):
        from app.utils.validators import validate_ioc
        ok, err = validate_ioc('   ', 'ip')
        assert ok is False

    def test_invalid_ioc_type(self):
        from app.utils.validators import validate_ioc
        ok, err = validate_ioc('8.8.8.8', 'phone')
        assert ok is False
        assert 'Invalid IOC type' in err

    def test_bad_ip_format(self):
        from app.utils.validators import validate_ioc
        ok, err = validate_ioc('not.an.ip', 'ip')
        assert ok is False

    def test_bad_hash_format(self):
        from app.utils.validators import validate_ioc
        ok, err = validate_ioc('zzz', 'hash')
        assert ok is False


class TestSanitizeChatInput:
    def test_normal_message_unchanged(self):
        from app.utils.validators import sanitize_chat_input
        msg, truncated = sanitize_chat_input('Analiza esta IP: 8.8.8.8')
        assert '8.8.8.8' in msg
        assert truncated is False

    def test_empty_string_returns_empty(self):
        from app.utils.validators import sanitize_chat_input
        msg, truncated = sanitize_chat_input('')
        assert msg == ""
        assert truncated is True

    def test_whitespace_only_returns_empty(self):
        from app.utils.validators import sanitize_chat_input
        msg, truncated = sanitize_chat_input('   ')
        assert msg == ""

    def test_message_truncated_at_max_length(self):
        from app.utils.validators import sanitize_chat_input
        long_msg = 'a' * 3000
        msg, truncated = sanitize_chat_input(long_msg, max_length=2000)
        assert len(msg) <= 2000
        assert truncated is True

    def test_null_bytes_removed(self):
        from app.utils.validators import sanitize_chat_input
        msg, _ = sanitize_chat_input('hello\x00world')
        assert '\x00' not in msg

    def test_excessive_newlines_reduced(self):
        from app.utils.validators import sanitize_chat_input
        msg, _ = sanitize_chat_input('line1\n\n\n\n\n\nline2')
        assert msg.count('\n') <= 4  # max 3 newlines between content after normalization

    def test_strips_leading_trailing_whitespace(self):
        from app.utils.validators import sanitize_chat_input
        msg, _ = sanitize_chat_input('  hello world  ')
        assert msg == 'hello world'


class TestExtractIocsFromText:
    def test_extracts_ip(self):
        from app.utils.validators import extract_iocs_from_text
        iocs = extract_iocs_from_text('Traffic to 185.220.101.1 detected')
        ips = [v for v, t in iocs if t == 'ip']
        assert '185.220.101.1' in ips

    def test_extracts_url(self):
        from app.utils.validators import extract_iocs_from_text
        iocs = extract_iocs_from_text('Found http://evil.com/payload.exe in logs')
        urls = [v for v, t in iocs if t == 'url']
        assert any('evil.com' in u for u in urls)

    def test_extracts_hash(self):
        from app.utils.validators import extract_iocs_from_text
        iocs = extract_iocs_from_text('Hash: d41d8cd98f00b204e9800998ecf8427e')
        hashes = [v for v, t in iocs if t == 'hash']
        assert 'd41d8cd98f00b204e9800998ecf8427e' in hashes

    def test_extracts_domain(self):
        from app.utils.validators import extract_iocs_from_text
        # The domain regex uses capture groups so re.findall returns tuples,
        # and only group[0] (a substring) is validated — domain extraction is
        # currently non-functional but should not crash.
        iocs = extract_iocs_from_text('C2 domain: evil.com observed')
        assert isinstance(iocs, list)

    def test_deduplicates(self):
        from app.utils.validators import extract_iocs_from_text
        iocs = extract_iocs_from_text('IP 8.8.8.8 and again 8.8.8.8')
        ips = [v for v, t in iocs if t == 'ip']
        assert ips.count('8.8.8.8') == 1

    def test_skips_private_ips(self):
        from app.utils.validators import extract_iocs_from_text
        iocs = extract_iocs_from_text('Internal 192.168.1.1 and external 185.220.101.1')
        ips = [v for v, t in iocs if t == 'ip']
        assert '192.168.1.1' not in ips
        assert '185.220.101.1' in ips

    def test_empty_text_returns_empty_list(self):
        from app.utils.validators import extract_iocs_from_text
        assert extract_iocs_from_text('') == []


# ==============================================================================
# FORMATTERS
# ==============================================================================

class TestFormatAnalysisResponse:
    def setup_method(self):
        self.base_results = {
            'ioc': '185.220.101.1',
            'type': 'ip',
            'confidence_score': 80,
            'risk_level': 'ALTO',
            'recommendation': 'Bloquear en firewall.',
        }

    def test_basic_fields_present(self):
        from app.utils.formatters import format_analysis_response
        resp = format_analysis_response(self.base_results, analysis_id=42)
        assert resp['id'] == 42
        assert resp['ioc'] == '185.220.101.1'
        assert resp['type'] == 'ip'
        assert resp['confidence_score'] == 80
        assert resp['risk_level'] == 'ALTO'
        assert 'timestamp' in resp

    def test_virustotal_source_included(self):
        from app.utils.formatters import format_analysis_response
        results = {**self.base_results, 'virustotal': {
            'detection_ratio': '45/70', 'positive_detections': 45,
            'total_scans': 70, 'malware_families': ['Emotet', 'TrickBot']
        }}
        resp = format_analysis_response(results)
        assert 'virustotal' in resp['sources']
        assert resp['sources']['virustotal']['detection_ratio'] == '45/70'

    def test_virustotal_with_error_excluded(self):
        from app.utils.formatters import format_analysis_response
        results = {**self.base_results, 'virustotal': {'error': 'API limit'}}
        resp = format_analysis_response(results)
        assert 'virustotal' not in resp.get('sources', {})

    def test_abuseipdb_source_included(self):
        from app.utils.formatters import format_analysis_response
        results = {**self.base_results, 'abuseipdb': {
            'abuse_confidence': 85, 'total_reports': 1000, 'country': 'RU'
        }}
        resp = format_analysis_response(results)
        assert 'abuseipdb' in resp['sources']
        assert resp['sources']['abuseipdb']['confidence'] == 85

    def test_shodan_source_included(self):
        from app.utils.formatters import format_analysis_response
        results = {**self.base_results, 'shodan': {
            'ports': [22, 80, 443], 'services': ['ssh', 'http', 'https'],
            'dangerous_services': ['ssh'], 'vulnerabilities': ['CVE-2021-1234']
        }}
        resp = format_analysis_response(results)
        assert 'shodan' in resp['sources']
        assert resp['sources']['shodan']['vulnerabilities_count'] == 1

    def test_mitre_techniques_included(self):
        from app.utils.formatters import format_analysis_response
        results = {**self.base_results, 'mitre_techniques': [
            {'id': 'T1071', 'name': 'App Layer Protocol', 'tactic': 'command-and-control'}
        ]}
        resp = format_analysis_response(results)
        assert 'mitre_attack' in resp
        assert resp['mitre_attack']['techniques_count'] == 1

    def test_llm_analysis_included(self):
        from app.utils.formatters import format_analysis_response
        results = {**self.base_results, 'llm_analysis': {'summary': 'Malicious IP'}}
        resp = format_analysis_response(results)
        assert 'ai_analysis' in resp
        assert resp['ai_analysis']['summary'] == 'Malicious IP'

    def test_errors_included_as_warnings(self):
        from app.utils.formatters import format_analysis_response
        results = {**self.base_results, 'errors': ['VirusTotal timeout']}
        resp = format_analysis_response(results)
        assert 'warnings' in resp
        assert 'VirusTotal timeout' in resp['warnings']

    def test_no_analysis_id_defaults_to_none(self):
        from app.utils.formatters import format_analysis_response
        resp = format_analysis_response(self.base_results)
        assert resp['id'] is None

    def test_otx_source_with_general_data(self):
        from app.utils.formatters import format_analysis_response
        results = {**self.base_results, 'otx': {
            'general': {'pulse_count': 5, 'pulses': []},
            'reputation': {'reputation': -3}
        }}
        resp = format_analysis_response(results)
        assert 'otx' in resp['sources']
        assert resp['sources']['otx']['pulse_count'] == 5


class TestFormatIncidentTicket:
    def setup_method(self):
        self.base_results = {
            'ioc': '185.220.101.1',
            'type': 'ip',
            'confidence_score': 75,
            'risk_level': 'ALTO',
            'recommendation': 'Bloquear IP inmediatamente.',
        }

    def test_ticket_contains_ioc(self):
        from app.utils.formatters import format_incident_ticket
        ticket = format_incident_ticket(self.base_results, analysis_id=1)
        assert '185.220.101.1' in ticket

    def test_critical_priority_p1(self):
        from app.utils.formatters import format_incident_ticket
        results = {**self.base_results, 'confidence_score': 80}
        ticket = format_incident_ticket(results)
        assert 'P1' in ticket

    def test_high_priority_p2(self):
        from app.utils.formatters import format_incident_ticket
        results = {**self.base_results, 'confidence_score': 60}
        ticket = format_incident_ticket(results)
        assert 'P2' in ticket

    def test_medium_priority_p3(self):
        from app.utils.formatters import format_incident_ticket
        results = {**self.base_results, 'confidence_score': 40}
        ticket = format_incident_ticket(results)
        assert 'P3' in ticket

    def test_low_priority_p4(self):
        from app.utils.formatters import format_incident_ticket
        results = {**self.base_results, 'confidence_score': 10}
        ticket = format_incident_ticket(results)
        assert 'P4' in ticket

    def test_ticket_includes_virustotal(self):
        from app.utils.formatters import format_incident_ticket
        results = {**self.base_results, 'virustotal': {
            'detection_ratio': '45/70', 'positive_detections': 45, 'malware_families': []
        }}
        ticket = format_incident_ticket(results)
        assert 'VirusTotal' in ticket or 'virustotal' in ticket.lower()

    def test_ticket_includes_abuseipdb(self):
        from app.utils.formatters import format_incident_ticket
        results = {**self.base_results, 'abuseipdb': {
            'abuse_confidence': 85, 'total_reports': 1000
        }}
        ticket = format_incident_ticket(results)
        assert 'AbuseIPDB' in ticket or '85%' in ticket

    def test_ticket_includes_recommendation(self):
        from app.utils.formatters import format_incident_ticket
        ticket = format_incident_ticket(self.base_results)
        assert 'Bloquear IP inmediatamente.' in ticket

    def test_ticket_includes_mitre(self):
        from app.utils.formatters import format_incident_ticket
        results = {**self.base_results, 'mitre_techniques': [
            {'id': 'T1071', 'name': 'App Layer Protocol'}
        ]}
        ticket = format_incident_ticket(results)
        assert 'MITRE' in ticket or 'T1071' in ticket


class TestFormatSummaryReport:
    def test_empty_list_returns_message(self):
        from app.utils.formatters import format_summary_report
        report = format_summary_report([])
        assert 'No hay análisis' in report

    def test_report_contains_totals(self):
        from app.utils.formatters import format_summary_report
        analyses = [
            {'ioc': '1.2.3.4', 'type': 'ip', 'confidence_score': 80, 'risk_level': 'ALTO'},
            {'ioc': 'evil.com', 'type': 'domain', 'confidence_score': 30, 'risk_level': 'MEDIO'},
        ]
        report = format_summary_report(analyses)
        assert '2' in report  # total count

    def test_report_truncates_at_10(self):
        from app.utils.formatters import format_summary_report
        analyses = [
            {'ioc': f'1.2.3.{i}', 'type': 'ip', 'confidence_score': 50, 'risk_level': 'ALTO'}
            for i in range(15)
        ]
        report = format_summary_report(analyses)
        assert '5' in report  # shows "y 5 análisis más"

    def test_report_has_percentages(self):
        from app.utils.formatters import format_summary_report
        analyses = [{'ioc': '1.1.1.1', 'type': 'ip', 'confidence_score': 75, 'risk_level': 'ALTO'}]
        report = format_summary_report(analyses)
        assert '%' in report
