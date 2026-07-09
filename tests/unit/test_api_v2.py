"""
Tests de API v2 — T3A-04
Cubre: /health, /analyze/enhanced, /chat/message, /sessions, /apis/status,
       /llm/providers, validación Pydantic (422), auth requerida, IDOR en sesiones
"""
import pytest
import json
from unittest.mock import patch, MagicMock
from datetime import datetime

BASE = '/api/v2'
HEADERS = {'Content-Type': 'application/json'}


def post_json(client, url, data):
    return client.post(url, data=json.dumps(data), headers=HEADERS)


def put_json(client, url, data):
    return client.put(url, data=json.dumps(data), headers=HEADERS)


# Resultado falso de analyze_with_intelligence para no llamar APIs reales
MOCK_ANALYSIS_RESULT = {
    'confidence_score': 75,
    'risk_level': 'ALTO',
    'api_results': {
        'virustotal': {'malicious': 30},
        'abuseipdb': {'abuse_confidence': 70},
    },
    'llm_analysis': {
        'summary': 'IP maliciosa detectada.',
        'recommendations': ['Bloquear en firewall'],
    },
    'sources_used': ['virustotal', 'abuseipdb'],
    'mitre_techniques': [],
    'processing_time': 1.23,
    'timestamp': datetime.utcnow().isoformat(),
}

MOCK_CHAT_RESULT = {
    'response': 'El IOC analizado presenta riesgo ALTO.',
    'requires_analysis': False,
    'analysis_data': None,
    'session_id': None,
    'session_title': None,
    'llm_provider': 'groq',
}


# ==============================================================================
# HEALTH CHECK (sin auth)
# ==============================================================================

class TestHealthCheck:

    def test_health_no_auth_required(self, client):
        """GET /api/v2/health devuelve 200 sin autenticación."""
        resp = client.get(f'{BASE}/health')
        assert resp.status_code == 200

    def test_health_contains_expected_fields(self, client):
        resp = client.get(f'{BASE}/health')
        data = resp.get_json()
        assert 'status' in data
        assert 'database' in data
        assert 'version' in data
        assert 'timestamp' in data

    def test_health_db_is_healthy(self, client, db_session):
        """Con DB disponible, el status debe ser healthy."""
        resp = client.get(f'{BASE}/health')
        data = resp.get_json()
        # El campo database puede ser string 'healthy' o dict {'status': 'healthy', ...}
        db_val = data['database']
        db_status = db_val if isinstance(db_val, str) else db_val.get('status', '')
        assert db_status == 'healthy'
        assert data['status'] == 'healthy'


# ==============================================================================
# AUTENTICACIÓN REQUERIDA
# ==============================================================================

class TestAuthRequired:

    def test_analyze_requires_login(self, client):
        resp = post_json(client, f'{BASE}/analyze/enhanced', {'ioc': '1.1.1.1', 'type': 'ip'})
        assert resp.status_code in (401, 302)

    def test_chat_requires_login(self, client):
        resp = post_json(client, f'{BASE}/chat/message', {'message': 'hello'})
        assert resp.status_code in (401, 302)

    def test_sessions_list_requires_login(self, client):
        resp = client.get(f'{BASE}/sessions')
        assert resp.status_code in (401, 302)

    def test_sessions_create_requires_login(self, client):
        resp = post_json(client, f'{BASE}/sessions', {})
        assert resp.status_code in (401, 302)

    def test_apis_status_requires_login(self, client):
        resp = client.get(f'{BASE}/apis/status')
        assert resp.status_code in (401, 302)

    def test_llm_providers_requires_login(self, client):
        resp = client.get(f'{BASE}/llm/providers')
        assert resp.status_code in (401, 302)


# ==============================================================================
# VALIDACIÓN PYDANTIC — /analyze/enhanced
# ==============================================================================

class TestAnalyzeValidation:

    def test_analyze_missing_ioc_returns_422(self, analyst_client):
        """Sin campo ioc → 422."""
        resp = post_json(analyst_client, f'{BASE}/analyze/enhanced', {'type': 'ip'})
        assert resp.status_code == 422
        data = resp.get_json()
        assert data['error'] == 'Validation error'
        assert any(e['field'] == 'ioc' for e in data['details'])

    def test_analyze_invalid_type_returns_422(self, analyst_client):
        """Tipo IOC no válido → 422."""
        resp = post_json(analyst_client, f'{BASE}/analyze/enhanced', {
            'ioc': '1.1.1.1',
            'type': 'telefono'
        })
        assert resp.status_code == 422

    def test_analyze_ioc_too_long_returns_422(self, analyst_client):
        """IOC mayor de 2048 chars → 422."""
        resp = post_json(analyst_client, f'{BASE}/analyze/enhanced', {
            'ioc': 'A' * 2049,
            'type': 'ip'
        })
        assert resp.status_code == 422

    def test_analyze_non_json_returns_400(self, analyst_client):
        """Sin Content-Type JSON → 400."""
        resp = analyst_client.post(f'{BASE}/analyze/enhanced', data='ioc=1.1.1.1')
        assert resp.status_code == 400

    def test_analyze_invalid_ip_format_returns_422(self, analyst_client):
        """IP con formato inválido cuando type=ip → 422."""
        resp = post_json(analyst_client, f'{BASE}/analyze/enhanced', {
            'ioc': 'not-an-ip',
            'type': 'ip'
        })
        assert resp.status_code == 422

    def test_analyze_invalid_hash_returns_422(self, analyst_client):
        """Hash que no es MD5/SHA1/SHA256 con type=hash → 422."""
        resp = post_json(analyst_client, f'{BASE}/analyze/enhanced', {
            'ioc': 'notahash123',
            'type': 'hash'
        })
        assert resp.status_code == 422

    def test_analyze_dangerous_chars_in_non_url_returns_422(self, analyst_client):
        """IOC con caracteres peligrosos en campo no-URL → 400 o 422."""
        resp = post_json(analyst_client, f'{BASE}/analyze/enhanced', {
            'ioc': '1.1.1.1; rm -rf /',
            'type': 'ip'
        })
        # El middleware de seguridad devuelve 400 (MALICIOUS_JSON); Pydantic devolvería 422
        assert resp.status_code in (400, 422)

    def test_analyze_valid_hash_sha256_accepted(self, analyst_client):
        """SHA256 válido con type=hash es aceptado por Pydantic (puede fallar en servicio)."""
        sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        with patch('app.routes.api_v2_routes.get_orchestrator') as mock_orch:
            mock_orch.return_value.analyze_with_intelligence.return_value = MOCK_ANALYSIS_RESULT
            with patch('app.services.ioc_cache.get_cached_analysis', return_value=None):
                resp = post_json(analyst_client, f'{BASE}/analyze/enhanced', {
                    'ioc': sha256,
                    'type': 'hash',
                    'use_llm_planning': False,
                })
        # No debe fallar en validación (422 o 400)
        assert resp.status_code != 422
        assert resp.status_code != 400

    def test_analyze_valid_ip_returns_200(self, analyst_client):
        """IP válida con mocks → 200 con campos esperados."""
        with patch('app.routes.api_v2_routes.get_orchestrator') as mock_orch:
            mock_orch.return_value.analyze_with_intelligence.return_value = MOCK_ANALYSIS_RESULT
            with patch('app.services.ioc_cache.get_cached_analysis', return_value=None):
                resp = post_json(analyst_client, f'{BASE}/analyze/enhanced', {
                    'ioc': '185.220.101.34',
                    'type': 'ip',
                    'use_llm_planning': False,
                })

        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert data['ioc'] == '185.220.101.34'
        assert data['type'] == 'ip'
        assert 'confidence_score' in data
        assert 'risk_level' in data

    def test_analyze_valid_domain_returns_200(self, analyst_client):
        """Dominio válido con mocks → 200."""
        with patch('app.routes.api_v2_routes.get_orchestrator') as mock_orch:
            mock_orch.return_value.analyze_with_intelligence.return_value = MOCK_ANALYSIS_RESULT
            with patch('app.services.ioc_cache.get_cached_analysis', return_value=None):
                resp = post_json(analyst_client, f'{BASE}/analyze/enhanced', {
                    'ioc': 'malware-c2.evil.com',
                    'type': 'domain',
                    'use_llm_planning': False,
                })
        assert resp.status_code == 200

    def test_analyze_cache_hit_returns_cached(self, analyst_client):
        """Si hay cache, devuelve datos cacheados sin llamar al orquestador."""
        cached = {**MOCK_ANALYSIS_RESULT, 'analysis_id': 99, 'ioc': '1.1.1.1', 'type': 'ip',
                  'cache_age_minutes': 5, 'timestamp': datetime.utcnow().isoformat()}
        with patch('app.services.ioc_cache.get_cached_analysis', return_value=cached):
            resp = post_json(analyst_client, f'{BASE}/analyze/enhanced', {
                'ioc': '1.1.1.1',
                'type': 'ip',
                'force_refresh': False,
            })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data.get('cached') is True
        assert data.get('cache_age_minutes') == 5

    def test_analyze_force_refresh_bypasses_cache(self, analyst_client):
        """force_refresh=True no consulta la cache."""
        with patch('app.routes.api_v2_routes.get_orchestrator') as mock_orch:
            mock_orch.return_value.analyze_with_intelligence.return_value = MOCK_ANALYSIS_RESULT
            with patch('app.services.ioc_cache.get_cached_analysis') as mock_cache:
                mock_cache.return_value = None
                resp = post_json(analyst_client, f'{BASE}/analyze/enhanced', {
                    'ioc': '1.1.1.1',
                    'type': 'ip',
                    'force_refresh': True,
                    'use_llm_planning': False,
                })
        # Cache no debe haber sido consultado
        mock_cache.assert_not_called()
        assert resp.status_code == 200


# ==============================================================================
# VALIDACIÓN — /chat/message
# ==============================================================================

class TestChatValidation:

    def test_chat_empty_message_returns_422_or_400(self, analyst_client):
        """Mensaje vacío → 422 (Pydantic) o 400."""
        resp = post_json(analyst_client, f'{BASE}/chat/message', {'message': ''})
        assert resp.status_code in (400, 422)

    def test_chat_message_too_long_returns_422(self, analyst_client):
        """Mensaje mayor a 10000 chars → 422."""
        resp = post_json(analyst_client, f'{BASE}/chat/message', {
            'message': 'X' * 10001
        })
        assert resp.status_code == 422

    def test_chat_invalid_provider_returns_422(self, analyst_client):
        """Proveedor LLM no válido → 422."""
        resp = post_json(analyst_client, f'{BASE}/chat/message', {
            'message': 'Analiza este IOC',
            'llm_provider': 'supergpt'
        })
        assert resp.status_code == 422

    def test_chat_missing_message_returns_422(self, analyst_client):
        """Sin campo message → 422."""
        resp = post_json(analyst_client, f'{BASE}/chat/message', {'session_id': 1})
        assert resp.status_code == 422

    def test_chat_non_json_returns_400(self, analyst_client):
        resp = analyst_client.post(f'{BASE}/chat/message', data='message=hello')
        assert resp.status_code == 400

    def test_chat_valid_message_returns_200(self, analyst_client):
        """Mensaje válido con mock → 200."""
        with patch('app.routes.api_v2_routes.get_orchestrator') as mock_orch:
            mock_orch.return_value.chat_analysis.return_value = MOCK_CHAT_RESULT
            resp = post_json(analyst_client, f'{BASE}/chat/message', {
                'message': 'Analiza la IP 185.220.101.34'
            })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert 'response' in data

    def test_chat_with_valid_provider_returns_200(self, analyst_client):
        """Proveedor válido (groq) con mock → 200."""
        with patch('app.routes.api_v2_routes.get_orchestrator') as mock_orch:
            mock_orch.return_value.chat_analysis.return_value = MOCK_CHAT_RESULT
            resp = post_json(analyst_client, f'{BASE}/chat/message', {
                'message': 'Resume la sesión',
                'llm_provider': 'groq'
            })
        assert resp.status_code == 200


# ==============================================================================
# SESIONES — CRUD e IDOR
# ==============================================================================

class TestSessions:

    def test_list_sessions_empty(self, analyst_client):
        """Lista sesiones de un usuario nuevo → array vacío."""
        resp = analyst_client.get(f'{BASE}/sessions')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert isinstance(data['sessions'], list)

    def test_create_session_success(self, analyst_client):
        """Crear sesión con título → 201."""
        resp = post_json(analyst_client, f'{BASE}/sessions', {
            'title': 'Investigación TTP APT29',
        })
        assert resp.status_code == 201
        data = resp.get_json()
        assert data['success'] is True
        assert data['session']['title'] == 'Investigación TTP APT29'

    def test_create_session_auto_title(self, analyst_client):
        """Crear sesión sin título → 201 con título generado."""
        resp = post_json(analyst_client, f'{BASE}/sessions', {})
        assert resp.status_code == 201
        assert resp.get_json()['success'] is True

    def test_get_own_session(self, analyst_client):
        """Usuario obtiene su propia sesión → 200."""
        create_resp = post_json(analyst_client, f'{BASE}/sessions', {'title': 'Mi Sesión'})
        session_id = create_resp.get_json()['session']['id']
        resp = analyst_client.get(f'{BASE}/sessions/{session_id}')
        assert resp.status_code == 200

    def test_get_nonexistent_session_returns_404(self, analyst_client):
        resp = analyst_client.get(f'{BASE}/sessions/99999')
        assert resp.status_code == 404

    def test_idor_other_user_cannot_get_session(self, analyst_client, other_client):
        """Otro usuario no puede ver sesión ajena → 403."""
        create_resp = post_json(analyst_client, f'{BASE}/sessions', {'title': 'Sesión privada'})
        assert create_resp.status_code == 201, f"POST falló: {create_resp.status_code} {create_resp.get_data(as_text=True)}"
        session_id = create_resp.get_json()['session']['id']
        resp = other_client.get(f'{BASE}/sessions/{session_id}')
        # NOTA: el check IDOR compara session.user_id con current_user.id vía Flask-Login
        assert resp.status_code == 403

    def test_idor_other_user_cannot_close_session(self, analyst_client, other_client):
        """Otro usuario no puede cerrar sesión ajena → 403."""
        create_resp = post_json(analyst_client, f'{BASE}/sessions', {'title': 'Sesión privada'})
        assert create_resp.status_code == 201, f"POST falló: {create_resp.status_code}"
        session_id = create_resp.get_json()['session']['id']
        resp = other_client.post(f'{BASE}/sessions/{session_id}/close', headers=HEADERS)
        assert resp.status_code == 403

    def test_admin_can_access_any_session(self, analyst_client, admin_client):
        """Admin puede ver sesiones de otros usuarios."""
        create_resp = post_json(analyst_client, f'{BASE}/sessions', {'title': 'Sesión de analista'})
        session_id = create_resp.get_json()['session']['id']
        resp = admin_client.get(f'{BASE}/sessions/{session_id}')
        assert resp.status_code == 200

    def test_close_session(self, analyst_client):
        """Cerrar sesión propia → 200."""
        create_resp = post_json(analyst_client, f'{BASE}/sessions', {'title': 'Cerrar'})
        session_id = create_resp.get_json()['session']['id']
        resp = analyst_client.post(f'{BASE}/sessions/{session_id}/close', headers=HEADERS)
        assert resp.status_code == 200

    def test_get_active_session(self, analyst_client):
        """GET /sessions/active devuelve la sesión activa o null."""
        resp = analyst_client.get(f'{BASE}/sessions/active')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'has_active' in data

    def test_list_sessions_after_create(self, analyst_client):
        """Después de crear sesión, aparece en el listado."""
        post_json(analyst_client, f'{BASE}/sessions', {'title': 'Nueva sesión'})
        resp = analyst_client.get(f'{BASE}/sessions')
        assert resp.status_code == 200
        assert resp.get_json()['total'] >= 1


# ==============================================================================
# APIS STATUS
# ==============================================================================

class TestApisStatus:

    def test_apis_status_returns_all_apis(self, analyst_client):
        resp = analyst_client.get(f'{BASE}/apis/status')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert 'apis' in data
        assert 'virustotal' in data['apis']
        assert 'abuseipdb' in data['apis']

    def test_apis_status_fields(self, analyst_client):
        resp = analyst_client.get(f'{BASE}/apis/status')
        vt = resp.get_json()['apis']['virustotal']
        assert 'health' in vt
        assert 'requests_today' in vt
        assert 'daily_limit' in vt
        assert 'is_configured' in vt

    def test_apis_status_counts(self, analyst_client):
        resp = analyst_client.get(f'{BASE}/apis/status')
        data = resp.get_json()
        assert data['total_apis'] > 0
        assert data['configured_apis'] >= 0


# ==============================================================================
# LLM PROVIDERS
# ==============================================================================

class TestLLMProviders:

    def test_llm_providers_returns_all(self, analyst_client):
        resp = analyst_client.get(f'{BASE}/llm/providers')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert 'xai' in data['providers']
        assert 'openai' in data['providers']
        assert 'groq' in data['providers']
        assert 'gemini' in data['providers']

    def test_llm_providers_fields(self, analyst_client):
        resp = analyst_client.get(f'{BASE}/llm/providers')
        for provider_data in resp.get_json()['providers'].values():
            assert 'available' in provider_data
            assert 'model' in provider_data
            assert 'speed' in provider_data


# ==============================================================================
# WHITELIST DE IOCs
# ==============================================================================

class TestWhitelist:

    def test_analyst_can_whitelist_ioc(self, analyst_client, db_session, sample_ioc):
        """POST /ioc/<id>/whitelist marca el IOC y guarda la razón."""
        resp = post_json(analyst_client, f'{BASE}/ioc/{sample_ioc.id}/whitelist',
                         {'reason': 'IP corporativa'})
        assert resp.status_code == 200

        from app.models.ioc import IOC
        ioc = db_session.session.get(IOC, sample_ioc.id)
        assert ioc.is_whitelisted is True
        assert ioc.whitelist_reason == 'IP corporativa'

    def test_analyst_can_remove_whitelist(self, analyst_client, db_session, sample_ioc):
        """DELETE /ioc/<id>/whitelist desmarca el IOC."""
        sample_ioc.is_whitelisted = True
        sample_ioc.whitelist_reason = 'test'
        db_session.session.commit()

        resp = analyst_client.delete(f'{BASE}/ioc/{sample_ioc.id}/whitelist')
        assert resp.status_code == 200

        from app.models.ioc import IOC
        ioc = db_session.session.get(IOC, sample_ioc.id)
        assert ioc.is_whitelisted is False
        assert ioc.whitelist_reason is None

    def test_whitelist_nonexistent_ioc_404(self, analyst_client):
        resp = post_json(analyst_client, f'{BASE}/ioc/999999/whitelist', {'reason': 'x'})
        assert resp.status_code == 404

    def test_viewer_cannot_whitelist(self, app, db_session, sample_ioc):
        """El rol viewer no puede modificar la whitelist (403 vía require_role)."""
        from app.models.ioc import User
        viewer = User(username='test_viewer', email='viewer@soc-test.local',
                      role='viewer', is_active=True)
        viewer.set_password('ViewerPass123!')
        db_session.session.add(viewer)
        db_session.session.commit()

        c = app.test_client()
        with c.session_transaction() as sess:
            sess['_user_id'] = str(viewer.id)
            sess['_fresh'] = True

        resp = c.post(f'{BASE}/ioc/{sample_ioc.id}/whitelist', json={'reason': 'x'})
        assert resp.status_code == 403

    def test_whitelisted_ioc_skips_analysis(self, analyst_client, db_session, sample_ioc):
        """Un IOC en whitelist corta el análisis antes de llamar APIs/LLM."""
        sample_ioc.is_whitelisted = True
        sample_ioc.whitelist_reason = 'IP interna'
        db_session.session.commit()

        resp = post_json(analyst_client, f'{BASE}/analyze/enhanced',
                         {'ioc': sample_ioc.value, 'type': 'ip'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data.get('whitelisted') is True
        assert data['whitelist_reason'] == 'IP interna'
