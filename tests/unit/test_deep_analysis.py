"""
Tests para el mini-agente de búsqueda web OSINT de Deep Analysis
(planificación de queries con LLM + búsqueda Tavily + síntesis).
Todas las llamadas externas (LLM y Tavily) van mockeadas.
"""
import pytest
from unittest.mock import patch, MagicMock


# ==============================================================================
# RATE LIMITING DE /deep/analyze
# Es más costoso que /analyze/enhanced (LLM + Tavily + N APIs): debe tener
# rate limiting equivalente. Se verifica la fuente en vez de disparar un
# request HTTP completo, para no tener que mockear todo el servicio.
# ==============================================================================

class TestDeepAnalyzeRateLimiting:

    def test_deep_analyze_has_rate_limit_and_login_decorators(self):
        import inspect
        from app.routes import deep_analysis_routes

        assert hasattr(deep_analysis_routes, 'limiter'), \
            "deep_analysis_routes debe importar `limiter` de app"

        source = inspect.getsource(deep_analysis_routes)
        decorator_block = source.split("def deep_analyze")[0].splitlines()[-6:]
        decorator_block_str = '\n'.join(decorator_block)

        assert '@login_required' in decorator_block_str
        assert '@limiter.limit' in decorator_block_str


@pytest.fixture(scope='function')
def svc(app):
    """DeepAnalysisService dentro de un app context."""
    with app.app_context():
        from app.services.deep_analysis_service import DeepAnalysisService
        yield DeepAnalysisService()


# ==============================================================================
# PASO 1: PLANIFICACIÓN DE QUERIES
# ==============================================================================

class TestPlanSearchQueries:

    def test_no_signals_uses_static_fallback(self, svc):
        """Sin señales de APIs no se gasta LLM: fallback estático con el IOC."""
        queries = svc._plan_search_queries('1.2.3.4', 'ip', {})
        assert len(queries) == 2
        assert any('1.2.3.4' in q for q in queries)

    def test_llm_list_response_is_used(self, svc):
        """El planner usa las queries del LLM (cap a 3)."""
        svc._llm_service = MagicMock()
        svc._llm_service._call_generic_openai_style.return_value = [
            'q1', 'q2', 'q3', 'q4'
        ]
        api_results = {'virustotal': {'malware_families': ['lockbit']}}
        queries = svc._plan_search_queries('1.2.3.4', 'ip', api_results)
        assert queries == ['q1', 'q2', 'q3']

    def test_llm_dict_with_json_array_is_parsed(self, svc):
        svc._llm_service = MagicMock()
        svc._llm_service._call_generic_openai_style.return_value = {
            'analysis': 'Aquí van: ["lockbit C2", "lockbit report"]'
        }
        api_results = {'threatfox': {'malware': 'LockBit'}}
        queries = svc._plan_search_queries('1.2.3.4', 'ip', api_results)
        assert queries == ['lockbit C2', 'lockbit report']

    def test_llm_failure_falls_back(self, svc):
        """Si el LLM lanza excepción, el fallback estático mantiene el flujo vivo."""
        svc._llm_service = MagicMock()
        svc._llm_service._call_generic_openai_style.side_effect = RuntimeError('boom')
        api_results = {'virustotal': {'malware_families': ['emotet']}}
        queries = svc._plan_search_queries('bad.example.com', 'domain', api_results)
        assert len(queries) == 2
        assert any('bad.example.com' in q for q in queries)


# ==============================================================================
# PASO 2: BÚSQUEDA + SÍNTESIS
# ==============================================================================

class TestWebSearchOsint:

    def test_without_tavily_key_only_reference_links(self, svc):
        """Sin API key: quedan los links de referencia, sin resultados ni resumen."""
        mock_client = MagicMock()
        mock_client.api_key = None
        with patch('app.services.new_api_clients.TavilySearchClient', return_value=mock_client):
            result = svc._web_search_osint('1.2.3.4', 'ip', api_results={})

        assert result['raw_results'] == []
        assert 'summary' not in result
        assert len(result['threat_reports']) > 0  # links estáticos siguen

    def test_results_deduped_and_summarized(self, svc):
        """Resultados de varias queries se deduplican por URL y se resumen."""
        mock_client = MagicMock()
        mock_client.api_key = 'test-key'
        mock_client.search.return_value = {
            'found': True, 'query': 'q',
            'results': [
                {'title': 'A', 'url': 'https://x/1', 'content': 'aaa', 'score': 0.9},
                {'title': 'A dup', 'url': 'https://x/1', 'content': 'aaa', 'score': 0.9},
                {'title': 'B', 'url': 'https://x/2', 'content': 'bbb', 'score': 0.8},
            ]
        }
        svc._llm_service = MagicMock()
        svc._llm_service._call_generic_openai_style.return_value = {'analysis': 'Resumen con citas'}

        with patch('app.services.new_api_clients.TavilySearchClient', return_value=mock_client):
            result = svc._web_search_osint(
                '1.2.3.4', 'ip',
                api_results={'virustotal': {'malware_families': ['lockbit']}}
            )

        urls = [r['url'] for r in result['raw_results']]
        assert urls.count('https://x/1') == 1  # dedupe
        assert result['summary'] == 'Resumen con citas'
        assert result['sources_found'] == urls

    def test_broad_retry_when_directed_queries_find_nothing(self, svc):
        """Si las queries dirigidas no hallan nada, se hace un reintento amplio."""
        mock_client = MagicMock()
        mock_client.api_key = 'test-key'
        # Todas las llamadas devuelven vacío
        mock_client.search.return_value = {'found': False, 'query': 'q', 'results': []}
        svc._llm_service = MagicMock()
        svc._llm_service._call_generic_openai_style.return_value = ['q1', 'q2']

        with patch('app.services.new_api_clients.TavilySearchClient', return_value=mock_client):
            result = svc._web_search_osint(
                '1.2.3.4', 'ip',
                api_results={'virustotal': {'malware_families': ['lockbit']}}
            )

        # 2 dirigidas + 1 amplia
        assert mock_client.search.call_count == 3
        broad_query = result['queries_used'][-1]
        assert 'lockbit' in broad_query
        # la amplia va SIN restricción de dominios
        last_call = mock_client.search.call_args_list[-1]
        assert last_call.kwargs.get('restrict_to_security_domains') is False

    def test_tavily_error_does_not_crash(self, svc):
        """Errores de Tavily (cuota, red) degradan con gracia, no rompen el análisis."""
        mock_client = MagicMock()
        mock_client.api_key = 'test-key'
        mock_client.search.return_value = {'error': 'Rate limit / cuota mensual de Tavily agotada'}

        with patch('app.services.new_api_clients.TavilySearchClient', return_value=mock_client):
            result = svc._web_search_osint('1.2.3.4', 'ip', api_results={})

        assert result['raw_results'] == []
        assert 'summary' not in result


# ==============================================================================
# CACHÉ / PERSISTENCIA DE BÚSQUEDA WEB
# ==============================================================================

class TestWebSearchCache:

    def test_persist_and_cache_roundtrip(self, app, db_session, sample_ioc, sample_analysis):
        from app.services.deep_analysis_service import DeepAnalysisService
        with app.app_context():
            svc = DeepAnalysisService()
            web = {'raw_results': [{'url': 'https://x/1'}], 'summary': 'resumen'}
            svc._persist_web_search(sample_ioc.value, sample_ioc.ioc_type, web)

            cached = svc._get_cached_web_search(sample_ioc.value, sample_ioc.ioc_type)
            assert cached is not None
            assert cached['summary'] == 'resumen'
            assert 'searched_at' in cached

    def test_expired_cache_returns_none(self, app, db_session, sample_ioc, sample_analysis):
        from datetime import timedelta
        from app.utils.time_utils import utcnow
        from app.services.deep_analysis_service import DeepAnalysisService
        with app.app_context():
            svc = DeepAnalysisService()
            old = (utcnow() - timedelta(hours=svc.WEB_SEARCH_TTL_HOURS + 1)).isoformat()
            sample_analysis.web_search_data = {'raw_results': [], 'searched_at': old}
            db_session.session.commit()

            assert svc._get_cached_web_search(sample_ioc.value, sample_ioc.ioc_type) is None

    def test_unknown_ioc_no_cache_no_crash(self, app, db_session):
        from app.services.deep_analysis_service import DeepAnalysisService
        with app.app_context():
            svc = DeepAnalysisService()
            assert svc._get_cached_web_search('99.99.99.99', 'ip') is None
            # persistir sin filas ancla es un no-op silencioso
            svc._persist_web_search('99.99.99.99', 'ip', {'raw_results': []})
