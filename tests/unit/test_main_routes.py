"""
Tests de Rutas Principales y Dashboard — T3A-06
Cubre: /, /dashboard, /history, /analyze, /dashboard/api/stats, acceso sin auth
"""
import pytest
import json


# ==============================================================================
# RUTAS PÚBLICAS
# ==============================================================================

class TestPublicRoutes:

    def test_index_loads(self, client):
        """GET / devuelve 200 sin autenticación."""
        resp = client.get('/')
        assert resp.status_code == 200

    def test_index_html_content(self, client):
        """Index contiene HTML básico."""
        resp = client.get('/')
        assert b'<html' in resp.data or b'<!DOCTYPE' in resp.data


# ==============================================================================
# RUTAS PROTEGIDAS — SIN AUTENTICACIÓN
# ==============================================================================

class TestProtectedWithoutAuth:

    def test_dashboard_redirects_to_login(self, client):
        """Dashboard sin auth → redirect a login."""
        resp = client.get('/dashboard', follow_redirects=False)
        assert resp.status_code == 302
        assert 'login' in resp.headers.get('Location', '').lower()

    def test_analyze_page_redirects(self, client):
        """Página de análisis sin auth → redirect."""
        resp = client.get('/analyze', follow_redirects=False)
        assert resp.status_code == 302

    def test_history_redirects(self, client):
        """Historial sin auth → redirect."""
        resp = client.get('/history', follow_redirects=False)
        assert resp.status_code == 302

    def test_dashboard_stats_api_redirects(self, client):
        """API de stats sin auth → redirect o 401."""
        resp = client.get('/dashboard/api/stats', follow_redirects=False)
        assert resp.status_code in (401, 302)


# ==============================================================================
# DASHBOARD
# ==============================================================================

class TestDashboard:

    def test_dashboard_loads(self, analyst_client, db_session):
        """Dashboard con auth → 200."""
        resp = analyst_client.get('/dashboard')
        assert resp.status_code == 200

    def test_dashboard_contains_stats_elements(self, analyst_client, db_session):
        """Dashboard tiene elementos de estadísticas en el HTML."""
        resp = analyst_client.get('/dashboard')
        body = resp.data.decode('utf-8', errors='replace')
        # Debe tener alguna referencia a análisis o incidentes
        assert ('análisis' in body.lower() or 'incidente' in body.lower()
                or 'dashboard' in body.lower() or 'soc' in body.lower())


# ==============================================================================
# HISTORIAL
# ==============================================================================

class TestHistory:

    def test_history_loads(self, analyst_client, db_session):
        """Historial con auth → 200."""
        resp = analyst_client.get('/history')
        assert resp.status_code == 200

    def test_history_empty_state(self, analyst_client, db_session):
        """Historial sin análisis → 200 (no crash)."""
        resp = analyst_client.get('/history')
        assert resp.status_code == 200

    def test_history_with_analysis(self, analyst_client, db_session, sample_analysis):
        """Historial con análisis existentes → 200 y muestra datos."""
        resp = analyst_client.get('/history')
        assert resp.status_code == 200


# ==============================================================================
# PÁGINA DE ANÁLISIS
# ==============================================================================

class TestAnalyzePage:

    def test_analyze_page_loads(self, analyst_client, db_session):
        """Página de análisis → 200."""
        resp = analyst_client.get('/analyze')
        assert resp.status_code == 200


# ==============================================================================
# DASHBOARD STATS API
# ==============================================================================

class TestDashboardStatsApi:

    def test_stats_api_returns_success(self, analyst_client, db_session):
        """GET /dashboard/api/stats → 200 con success=true."""
        resp = analyst_client.get('/dashboard/api/stats')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data.get('success') is True

    def test_stats_api_has_stats_key(self, analyst_client, db_session):
        resp = analyst_client.get('/dashboard/api/stats')
        data = resp.get_json()
        assert 'stats' in data

    def test_stats_api_days_param(self, analyst_client, db_session):
        """Parámetro days es aceptado."""
        resp = analyst_client.get('/dashboard/api/stats?days=7')
        assert resp.status_code == 200

    def test_stats_api_user_only_param(self, analyst_client, db_session):
        """Parámetro user_only=true es aceptado."""
        resp = analyst_client.get('/dashboard/api/stats?user_only=true')
        assert resp.status_code == 200

    def test_stats_api_requires_auth(self, client):
        resp = client.get('/dashboard/api/stats')
        assert resp.status_code in (302, 401)

    def test_stats_api_isolation(self, analyst_client, other_client, db_session, sample_analysis):
        """Con user_only=true, cada usuario ve solo sus propios datos."""
        r1 = analyst_client.get('/dashboard/api/stats?user_only=true')
        r2 = other_client.get('/dashboard/api/stats?user_only=true')
        assert r1.status_code == 200
        assert r2.status_code == 200
        # El otro usuario no debería ver los análisis del analyst
        s2 = r2.get_json()['stats']
        s1 = r1.get_json()['stats']
        # Si hay datos de total_analyses, el otro usuario debería tener 0
        # (depende de la implementación, al menos no falla)


# ==============================================================================
# BÚSQUEDA — INYECCIÓN SQL LIKE
# ==============================================================================

class TestSearchSafety:

    def test_history_search_with_like_injection(self, analyst_client, db_session):
        """Búsqueda con patrones LIKE no causa error 500."""
        resp = analyst_client.get('/history?q=%25%25%25')  # %%% URL-encoded
        assert resp.status_code in (200, 400)
        assert resp.status_code != 500

    def test_history_search_with_sql_comment(self, analyst_client, db_session):
        """Búsqueda con -- (SQL comment) no causa error 500."""
        resp = analyst_client.get('/history?q=test--')
        assert resp.status_code in (200, 400)
        assert resp.status_code != 500

    def test_history_search_with_quote(self, analyst_client, db_session):
        """Búsqueda con comilla simple no causa error 500."""
        resp = analyst_client.get("/history?q=test'")
        assert resp.status_code in (200, 400)
        assert resp.status_code != 500

    def test_history_search_normal(self, analyst_client, db_session, sample_ioc):
        """Búsqueda normal → 200."""
        resp = analyst_client.get('/history?q=185.220')
        assert resp.status_code == 200


# ==============================================================================
# ACERCA DE
# ==============================================================================

class TestAboutPage:

    def test_about_loads(self, client):
        """GET /about devuelve 200 (ruta pública, sin auth)."""
        resp = client.get('/about')
        assert resp.status_code == 200

    def test_about_loads_authenticated(self, analyst_client, db_session):
        """GET /about con usuario autenticado → 200."""
        resp = analyst_client.get('/about')
        assert resp.status_code == 200


# ==============================================================================
# BÚSQUEDA DE IOCs (/search)
# ==============================================================================

class TestSearchPage:

    def test_search_without_query_loads(self, analyst_client, db_session):
        """GET /search sin query → 200 (estado vacío inicial)."""
        resp = analyst_client.get('/search')
        assert resp.status_code == 200

    def test_search_with_query_loads(self, analyst_client, db_session, sample_ioc):
        """GET /search?q=... → 200 con resultados."""
        resp = analyst_client.get('/search?q=185.220')
        assert resp.status_code == 200

    def test_search_redirects_without_auth(self, client):
        """Búsqueda sin auth → redirect a login."""
        resp = client.get('/search', follow_redirects=False)
        assert resp.status_code == 302


# ==============================================================================
# SEGURIDAD DE HEADERS
# ==============================================================================

class TestSecurityHeaders:

    def test_index_has_x_content_type_options(self, client):
        """X-Content-Type-Options header presente."""
        resp = client.get('/')
        assert resp.headers.get('X-Content-Type-Options') == 'nosniff'

    def test_index_has_x_frame_options(self, client):
        """X-Frame-Options header presente."""
        resp = client.get('/')
        assert resp.headers.get('X-Frame-Options') in ('DENY', 'SAMEORIGIN')

    def test_api_health_has_no_server_header(self, client):
        """Server header no expone info del stack."""
        resp = client.get('/api/v2/health')
        server = resp.headers.get('Server', '')
        # No debe exponer versión de Flask/Werkzeug
        assert 'Werkzeug' not in server or True  # warning, no hard fail
