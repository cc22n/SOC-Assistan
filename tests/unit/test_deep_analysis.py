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


# ==============================================================================
# PERSISTENCIA DEL RESULTADO DE DEEP ANALYSIS (IOC + IOCAnalysis + SessionIOC)
#
# Antes de este fix, deep_analyze() calculaba base_analysis (score, risk_level,
# APIs) pero nunca creaba filas IOC/IOCAnalysis/SessionIOC: una pregunta de
# seguimiento en el chat ("¿qué puertos tiene?") no encontraba el IOC vía
# _get_session_ioc_data y perdía todo el contexto del deep analysis.
# ==============================================================================

MOCK_BASE_ANALYSIS = {
    'confidence_score': 75,
    'risk_level': 'ALTO',
    'api_results': {
        'virustotal': {'malicious': 30},
        'abuseipdb': {'abuse_confidence': 70},
    },
    'llm_analysis': {'summary': 'IP maliciosa detectada.'},
    'sources_used': ['virustotal', 'abuseipdb'],
    'mitre_techniques': [],
    'processing_time': 1.23,
}


class TestDeepAnalyzePersistence:
    """Verifica que deep_analyze() persiste su resultado reutilizando el mismo
    helper que usa el flujo normal de chat (_save_analysis_to_session), sin
    llamar APIs/LLM/Tavily reales."""

    @staticmethod
    def _make_service(base_analysis=None):
        from app.services.deep_analysis_service import DeepAnalysisService
        svc = DeepAnalysisService()

        # Paso 6 (reporte final) siempre llama al LLM: mockeado.
        svc._llm_service = MagicMock()
        svc._llm_service._call_generic_openai_style.return_value = {'analysis': '{}'}

        # El orchestrator queda REAL (para reusar _save_analysis_to_session tal
        # cual), solo se mockea la llamada cara a APIs externas + LLM planning.
        real_orchestrator = svc.orchestrator
        real_orchestrator.analyze_with_intelligence = MagicMock(
            return_value=dict(base_analysis or MOCK_BASE_ANALYSIS)
        )
        return svc

    def test_new_ioc_creates_ioc_and_analysis_rows(self, app, db_session, analyst_user):
        """REST sin session_id: igual persiste IOC + IOCAnalysis."""
        with app.app_context():
            svc = self._make_service()

            result = svc.deep_analyze(
                ioc='203.0.113.77',
                ioc_type='ip',
                user_id=analyst_user.id,
                session_id=None,
                include_web_search=False,
                include_correlation=False,
                include_apt_analysis=False,
                include_hypothesis=False,
            )

            from app.models.ioc import IOC, IOCAnalysis

            ioc_obj = IOC.query.filter_by(value='203.0.113.77', ioc_type='ip').first()
            assert ioc_obj is not None, "deep_analyze debe crear la fila IOC"

            analysis = IOCAnalysis.query.filter_by(ioc_id=ioc_obj.id).first()
            assert analysis is not None, "deep_analyze debe crear la fila IOCAnalysis"
            assert analysis.risk_level == 'ALTO'
            assert analysis.confidence_score == 75
            assert result.get('ioc_analysis_id') == analysis.id
            assert 'persisted' in result['modules_executed']

    def test_persistence_links_session_ioc_when_session_id_given(self, app, db_session, analyst_user):
        """Chat con sesión: además crea el SessionIOC, para que el seguimiento
        (_get_session_ioc_data) encuentre el IOC."""
        with app.app_context():
            from app.models.session import InvestigationSession, SessionIOC
            from app import db

            session_obj = InvestigationSession(user_id=analyst_user.id, title='test session')
            db.session.add(session_obj)
            db.session.commit()

            svc = self._make_service()

            svc.deep_analyze(
                ioc='198.51.100.23',
                ioc_type='ip',
                user_id=analyst_user.id,
                session_id=session_obj.id,
                include_web_search=False,
                include_correlation=False,
                include_apt_analysis=False,
                include_hypothesis=False,
            )

            from app.models.ioc import IOC

            ioc_obj = IOC.query.filter_by(value='198.51.100.23', ioc_type='ip').first()
            assert ioc_obj is not None

            sioc = SessionIOC.query.filter_by(session_id=session_obj.id, ioc_id=ioc_obj.id).first()
            assert sioc is not None, "debe vincular el IOC a la sesión vía SessionIOC"
            assert sioc.analysis_id is not None

            # Simula la pregunta de seguimiento en el chat tras el deep analysis
            ioc_value, ioc_type, api_data = svc.orchestrator._get_session_ioc_data(
                session_obj.id, '198.51.100.23'
            )
            assert ioc_value == '198.51.100.23'
            assert ioc_type == 'ip'

    def test_existing_ioc_is_updated_not_duplicated(self, app, db_session, sample_ioc, analyst_user):
        """Si el IOC ya existe (mismo value+type), el helper hace upsert del IOC
        (no duplica la fila IOC); el IOCAnalysis nuevo se agrega al historial,
        igual que en el flujo normal de chat."""
        with app.app_context():
            svc = self._make_service(
                base_analysis=dict(MOCK_BASE_ANALYSIS, risk_level='CRÍTICO', confidence_score=95)
            )

            svc.deep_analyze(
                ioc=sample_ioc.value,
                ioc_type=sample_ioc.ioc_type,
                user_id=analyst_user.id,
                session_id=None,
                include_web_search=False,
                include_correlation=False,
                include_apt_analysis=False,
                include_hypothesis=False,
            )

            from app.models.ioc import IOC, IOCAnalysis

            matching_iocs = IOC.query.filter_by(
                value=sample_ioc.value, ioc_type=sample_ioc.ioc_type
            ).all()
            assert len(matching_iocs) == 1, "no debe duplicar la fila IOC"

            analyses = IOCAnalysis.query.filter_by(ioc_id=sample_ioc.id).all()
            assert len(analyses) >= 1
            latest = max(analyses, key=lambda a: a.id)
            assert latest.risk_level == 'CRÍTICO'

    def test_persistence_failure_does_not_break_deep_analysis(self, app, db_session, analyst_user):
        """Si la persistencia falla (p.ej. BD caída), el deep analysis debe
        seguir devolviendo el reporte en vez de romperse."""
        with app.app_context():
            svc = self._make_service()
            svc.orchestrator._save_analysis_to_session = MagicMock(
                side_effect=RuntimeError('DB down')
            )

            result = svc.deep_analyze(
                ioc='203.0.113.200',
                ioc_type='ip',
                user_id=analyst_user.id,
                session_id=None,
                include_web_search=False,
                include_correlation=False,
                include_apt_analysis=False,
                include_hypothesis=False,
            )

            assert 'base_analysis' in result
            assert result['base_analysis']['risk_level'] == 'ALTO'
            assert 'ioc_analysis_id' not in result
            assert 'persisted' not in result['modules_executed']
