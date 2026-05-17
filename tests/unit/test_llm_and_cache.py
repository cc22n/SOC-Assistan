"""
Tests para LLMService y ioc_cache — mock external LLM calls
Cubre: app/services/llm_service.py, app/services/ioc_cache.py
"""
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta


# ==============================================================================
# LLM SERVICE TESTS
# ==============================================================================

@pytest.fixture(scope='function')
def app_ctx(app):
    """Push an app context for tests that need current_app."""
    with app.app_context():
        yield


def make_response(status, json_data):
    m = MagicMock()
    m.status_code = status
    m.json.return_value = json_data
    m.text = str(json_data)
    return m


class TestLLMServiceDetection:

    def test_detects_xai_first(self, app, app_ctx):
        from flask import current_app
        from app.services.llm_service import LLMService
        current_app.config['API_KEYS']['xai'] = 'test-xai-key'
        svc = LLMService()
        assert svc.provider == 'xai'

    def test_detects_groq_when_no_xai(self, app, app_ctx):
        from flask import current_app
        from app.services.llm_service import LLMService
        original_xai = current_app.config['API_KEYS'].get('xai')
        current_app.config['API_KEYS']['xai'] = None
        try:
            current_app.config['API_KEYS']['groq'] = 'test-groq-key'
            svc = LLMService()
            assert svc.provider in ('groq', 'openai', 'gemini', 'anthropic')
        finally:
            current_app.config['API_KEYS']['xai'] = original_xai

    def test_explicit_provider_overrides_detection(self, app_ctx):
        from app.services.llm_service import LLMService
        svc = LLMService(provider='groq')
        assert svc.provider == 'groq'

    def test_configure_groq_sets_base_url(self, app_ctx):
        from app.services.llm_service import LLMService
        svc = LLMService(provider='groq')
        assert 'groq' in svc.base_url

    def test_configure_openai_sets_base_url(self, app_ctx):
        from app.services.llm_service import LLMService
        svc = LLMService(provider='openai')
        assert 'openai' in svc.base_url

    def test_configure_gemini_sets_base_url(self, app_ctx):
        from app.services.llm_service import LLMService
        svc = LLMService(provider='gemini')
        assert 'google' in svc.base_url

    def test_configure_anthropic_sets_base_url(self, app_ctx):
        from app.services.llm_service import LLMService
        svc = LLMService(provider='anthropic')
        assert 'anthropic' in svc.base_url

    def test_configure_xai_sets_base_url(self, app_ctx):
        from app.services.llm_service import LLMService
        svc = LLMService(provider='xai')
        assert 'x.ai' in svc.base_url


class TestLLMServiceAnalyze:

    def test_fallback_when_no_provider(self, app, app_ctx):
        from flask import current_app
        from app.services.llm_service import LLMService
        # Temporarily null all API keys
        original = dict(current_app.config['API_KEYS'])
        for k in ('xai', 'openai', 'groq', 'gemini', 'anthropic'):
            current_app.config['API_KEYS'][k] = None
        try:
            svc = LLMService()
            result = svc.analyze_context({'ioc': '8.8.8.8', 'type': 'ip', 'confidence_score': 50})
            assert 'note' in result or 'summary' in result
        finally:
            current_app.config['API_KEYS'].update(original)

    def test_analyze_groq_success(self, app_ctx):
        from app.services.llm_service import LLMService
        svc = LLMService(provider='groq')
        svc.api_key = 'test-key'

        mock_resp = make_response(200, {
            'choices': [{'message': {'content': '{"summary": "IP maliciosa", "threat_level": "ALTO", "recommendations": ["Bloquear"]}'}}]
        })
        with patch('requests.post', return_value=mock_resp):
            result = svc.analyze_context({'ioc': '185.220.101.1', 'type': 'ip', 'confidence_score': 80})
        assert 'summary' in result
        assert result['summary'] == 'IP maliciosa'

    def test_analyze_openai_success(self, app_ctx):
        from app.services.llm_service import LLMService
        svc = LLMService(provider='openai')
        svc.api_key = 'test-key'

        mock_resp = make_response(200, {
            'choices': [{'message': {'content': '{"summary": "Dominio sospechoso", "threat_level": "MEDIO", "recommendations": []}'}}]
        })
        with patch('requests.post', return_value=mock_resp):
            result = svc.analyze_context({'ioc': 'evil.com', 'type': 'domain', 'confidence_score': 55})
        assert 'summary' in result

    def test_analyze_xai_success(self, app_ctx):
        from app.services.llm_service import LLMService
        svc = LLMService(provider='xai')
        svc.api_key = 'test-key'

        mock_resp = make_response(200, {
            'choices': [{'message': {'content': '{"summary": "Grok analysis", "threat_level": "BAJO", "recommendations": []}'}}]
        })
        with patch('requests.post', return_value=mock_resp):
            result = svc.analyze_context({'ioc': '1.2.3.4', 'type': 'ip', 'confidence_score': 20})
        assert 'summary' in result

    def test_analyze_anthropic_success(self, app_ctx):
        from app.services.llm_service import LLMService
        svc = LLMService(provider='anthropic')
        svc.api_key = 'test-key'

        mock_resp = make_response(200, {
            'content': [{'text': '{"summary": "Claude analysis", "threat_level": "ALTO", "recommendations": ["Block IP"]}'}]
        })
        with patch('requests.post', return_value=mock_resp):
            result = svc.analyze_context({'ioc': '185.220.101.1', 'type': 'ip', 'confidence_score': 85})
        assert 'summary' in result
        assert result['summary'] == 'Claude analysis'

    def test_analyze_gemini_success(self, app_ctx):
        from app.services.llm_service import LLMService
        svc = LLMService(provider='gemini')
        svc.api_key = 'test-key'

        mock_resp = make_response(200, {
            'candidates': [{'content': {'parts': [{'text': '{"summary": "Gemini analysis", "threat_level": "ALTO", "recommendations": []}'}]}}]
        })
        with patch('requests.post', return_value=mock_resp):
            result = svc.analyze_context({'ioc': 'evil.com', 'type': 'domain', 'confidence_score': 70})
        assert 'summary' in result

    def test_analyze_groq_api_error(self, app_ctx):
        from app.services.llm_service import LLMService
        svc = LLMService(provider='groq')
        svc.api_key = 'test-key'

        with patch('requests.post', return_value=make_response(429, {'error': 'Rate limit'})):
            result = svc.analyze_context({'ioc': '1.2.3.4', 'type': 'ip', 'confidence_score': 50})
        assert 'error' in result

    def test_analyze_anthropic_api_error(self, app_ctx):
        from app.services.llm_service import LLMService
        svc = LLMService(provider='anthropic')
        svc.api_key = 'test-key'

        with patch('requests.post', return_value=make_response(401, {'error': 'Invalid key'})):
            result = svc.analyze_context({'ioc': '1.2.3.4', 'type': 'ip', 'confidence_score': 50})
        assert 'error' in result

    def test_analyze_gemini_no_candidates(self, app_ctx):
        from app.services.llm_service import LLMService
        svc = LLMService(provider='gemini')
        svc.api_key = 'test-key'

        with patch('requests.post', return_value=make_response(200, {'candidates': []})):
            result = svc.analyze_context({'ioc': 'test.com', 'type': 'domain', 'confidence_score': 0})
        assert 'error' in result

    def test_analyze_exception_returns_error(self, app_ctx):
        from app.services.llm_service import LLMService
        svc = LLMService(provider='groq')
        svc.api_key = 'test-key'

        with patch('requests.post', side_effect=Exception('Connection error')):
            result = svc.analyze_context({'ioc': '1.2.3.4', 'type': 'ip', 'confidence_score': 50})
        # Exception caught at analyze_context level → {'error': '...'}
        assert 'error' in result


class TestLLMExtractJson:

    def test_extract_valid_json(self, app_ctx):
        from app.services.llm_service import LLMService
        svc = LLMService(provider='groq')
        result = svc._extract_json('{"summary": "test", "threat_level": "ALTO"}')
        assert result['summary'] == 'test'

    def test_extract_json_with_surrounding_text(self, app_ctx):
        from app.services.llm_service import LLMService
        svc = LLMService(provider='groq')
        result = svc._extract_json('Here is the analysis:\n{"summary": "evil IP"}\nDone.')
        assert 'summary' in result

    def test_extract_json_fallback_to_raw(self, app_ctx):
        from app.services.llm_service import LLMService
        svc = LLMService(provider='groq')
        result = svc._extract_json('Just a plain text response with no JSON')
        assert 'analysis' in result
        assert result.get('raw_text') is True

    def test_build_prompt_sanitizes_ioc(self, app_ctx):
        from app.services.llm_service import LLMService
        svc = LLMService(provider='groq')
        ioc_data = {'ioc': '8.8.8.8<script>', 'type': 'ip', 'confidence_score': 50}
        prompt = svc._build_prompt(ioc_data)
        assert '<script>' not in prompt

    def test_build_prompt_sanitizes_type(self, app_ctx):
        from app.services.llm_service import LLMService
        svc = LLMService(provider='groq')
        # re.sub(r'[^\w]', '', 'ip; DROP TABLE users') strips ; and spaces
        # resulting in 'ipDROPTABLEusers' — special chars removed, word chars kept
        ioc_data = {'ioc': '1.2.3.4', 'type': 'ip; DROP TABLE users', 'confidence_score': 50}
        prompt = svc._build_prompt(ioc_data)
        assert '; DROP' not in prompt  # semicolon+space injection removed


# ==============================================================================
# IOC CACHE TESTS
# ==============================================================================

class TestGetEffectiveTtl:

    def test_critical_ip_uses_minimum(self):
        from app.services.ioc_cache import _get_effective_ttl
        # CRÍTICO=1h, ip=1h → min=1
        assert _get_effective_ttl('CRÍTICO', 'ip') == 1

    def test_critical_hash_uses_risk_ttl(self):
        from app.services.ioc_cache import _get_effective_ttl
        # CRÍTICO=1h, hash=24h → min=1
        assert _get_effective_ttl('CRÍTICO', 'hash') == 1

    def test_clean_ip_uses_type_ttl(self):
        from app.services.ioc_cache import _get_effective_ttl
        # LIMPIO=24h, ip=1h → min=1
        assert _get_effective_ttl('LIMPIO', 'ip') == 1

    def test_clean_domain_uses_min(self):
        from app.services.ioc_cache import _get_effective_ttl
        # LIMPIO=24h, domain=6h → min=6
        assert _get_effective_ttl('LIMPIO', 'domain') == 6

    def test_unknown_risk_uses_default(self):
        from app.services.ioc_cache import _get_effective_ttl
        # Unknown risk → DEFAULT_TTL_HOURS=6; domain=6h → min=6
        assert _get_effective_ttl('UNKNOWN_RISK', 'domain') == 6

    def test_medio_hash_uses_min(self):
        from app.services.ioc_cache import _get_effective_ttl
        # MEDIO=6h, hash=24h → min=6
        assert _get_effective_ttl('MEDIO', 'hash') == 6


class TestGetCachedAnalysis:

    def test_force_refresh_returns_none(self, app, db_session):
        from app.services.ioc_cache import get_cached_analysis
        with app.app_context():
            result = get_cached_analysis('1.2.3.4', 'ip', force_refresh=True)
            assert result is None

    def test_no_ioc_in_db_returns_none(self, app, db_session):
        from app.services.ioc_cache import get_cached_analysis
        with app.app_context():
            result = get_cached_analysis('999.999.999.999', 'ip')
            assert result is None

    def test_cache_hit_returns_data(self, app, db_session, analyst_user):
        from app.models.ioc import IOC, IOCAnalysis
        from app.services.ioc_cache import get_cached_analysis

        with app.app_context():
            ioc = IOC(value='185.220.101.1', ioc_type='ip')
            db_session.session.add(ioc)
            db_session.session.flush()

            analysis = IOCAnalysis(
                ioc_id=ioc.id,
                user_id=analyst_user.id,
                confidence_score=90,
                risk_level='ALTO',
                recommendation='Block',
                sources_used=['virustotal'],
                processing_time=1.5,
            )
            # Set created_at to 10 minutes ago (well within TTL)
            analysis.created_at = datetime.utcnow() - timedelta(minutes=10)
            db_session.session.add(analysis)
            db_session.session.commit()

            result = get_cached_analysis('185.220.101.1', 'ip')
            assert result is not None
            assert result['cached'] is True
            assert result['risk_level'] == 'ALTO'
            assert result['ioc'] == '185.220.101.1'

    def test_cache_miss_when_expired(self, app, db_session, analyst_user):
        from app.models.ioc import IOC, IOCAnalysis
        from app.services.ioc_cache import get_cached_analysis

        with app.app_context():
            ioc = IOC(value='10.0.0.1', ioc_type='ip')
            db_session.session.add(ioc)
            db_session.session.flush()

            analysis = IOCAnalysis(
                ioc_id=ioc.id,
                user_id=analyst_user.id,
                confidence_score=30,
                risk_level='BAJO',
                recommendation='Monitor',
                sources_used=['abuseipdb'],
                processing_time=0.5,
            )
            # Set created_at to 48 hours ago (well past all TTLs)
            analysis.created_at = datetime.utcnow() - timedelta(hours=48)
            db_session.session.add(analysis)
            db_session.session.commit()

            result = get_cached_analysis('10.0.0.1', 'ip')
            assert result is None

    def test_cache_hit_with_custom_max_age(self, app, db_session, analyst_user):
        from app.models.ioc import IOC, IOCAnalysis
        from app.services.ioc_cache import get_cached_analysis

        with app.app_context():
            ioc = IOC(value='77.77.77.77', ioc_type='ip')
            db_session.session.add(ioc)
            db_session.session.flush()

            analysis = IOCAnalysis(
                ioc_id=ioc.id,
                user_id=analyst_user.id,
                confidence_score=60,
                risk_level='MEDIO',
                recommendation='Review',
                sources_used=['shodan'],
                processing_time=2.0,
            )
            analysis.created_at = datetime.utcnow() - timedelta(hours=2)
            db_session.session.add(analysis)
            db_session.session.commit()

            # max_age_hours=3 → should hit (age=2h < 3h)
            result = get_cached_analysis('77.77.77.77', 'ip', max_age_hours=3)
            assert result is not None

            # max_age_hours=1 → should miss (age=2h > 1h)
            result2 = get_cached_analysis('77.77.77.77', 'ip', max_age_hours=1)
            assert result2 is None


class TestGetCacheStats:

    def test_cache_stats_returns_dict(self, app, db_session):
        from app.services.ioc_cache import get_cache_stats
        with app.app_context():
            stats = get_cache_stats()
            assert isinstance(stats, dict)
            assert 'total_analyses' in stats
            assert 'last_hour' in stats
            assert 'last_24h' in stats
            assert 'active_cached_iocs' in stats

    def test_cache_stats_with_empty_db(self, app, db_session):
        from app.services.ioc_cache import get_cache_stats
        with app.app_context():
            stats = get_cache_stats()
            assert stats['total_analyses'] == 0
