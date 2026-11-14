"""
Regresión de los hallazgos de autorización de full-audit-report.md (verificados abiertos
el 2026-11-13):
  CRIT-01  IDOR en /api/v2/deep/analyze (session_id ajeno)
  CRIT-02  Chat (viewer) evadía RBAC disparando deep analysis
  CRIT-03  viewer podía mutar incidentes
  CRIT-04  /search filtraba análisis/IOCs de otros usuarios
"""
from unittest.mock import MagicMock, patch

import pytest

from app.models.audit import AuditEvent
from app.models.ioc import IOC, IOCAnalysis, Incident, User
from app.models.session import InvestigationSession


# ------------------------------------------------------------------ helpers

def _client_for(app, db_session, username, role):
    user = User(username=username, email=f'{username}@soc-test.local', role=role, is_active=True)
    user.set_password('Passw0rd!Test1')
    db_session.session.add(user)
    db_session.session.commit()
    c = app.test_client()
    with c.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True
    return c, user


@pytest.fixture
def viewer(app, db_session):
    return _client_for(app, db_session, 'authz_viewer', 'viewer')


@pytest.fixture
def senior(app, db_session):
    return _client_for(app, db_session, 'authz_senior', 'senior_analyst')


# ------------------------------------------------------------------ CRIT-03

class TestViewerCannotMutateIncidents:
    def test_viewer_no_puede_crear(self, viewer):
        c, _ = viewer
        r = c.post('/api/v2/incidents', json={'title': 'Incidente de prueba', 'severity': 'P3'})
        assert r.status_code == 403

    @pytest.mark.parametrize('method,path,body', [
        ('put', '/api/v2/incidents/{id}', {'title': 'Nuevo título'}),
        ('put', '/api/v2/incidents/{id}/status', {'status': 'closed'}),
        ('post', '/api/v2/incidents/{id}/notes', {'content': 'nota'}),
        ('post', '/api/v2/incidents/{id}/iocs', {'ioc_ids': [1]}),
        ('delete', '/api/v2/incidents/{id}/iocs/1', None),
    ])
    def test_viewer_no_puede_mutar(self, app, db_session, viewer, method, path, body):
        # El incidente es DEL PROPIO viewer: así el chequeo de visibilidad no lo frena
        # y solo el RBAC puede devolver 403.
        c, user = viewer
        inc = Incident(ticket_id='SOC-VIEWER-OWN', title='Propio del viewer', severity='P3',
                       status='open', created_by=user.id)
        db_session.session.add(inc)
        db_session.session.commit()
        url = path.format(id=inc.id)
        kw = {'json': body} if body is not None else {}
        r = getattr(c, method)(url, **kw)
        assert r.status_code == 403
        db_session.session.refresh(inc)
        assert inc.status == 'open' and inc.title == 'Propio del viewer'

    def test_analyst_sigue_pudiendo_crear(self, analyst_client):
        r = analyst_client.post('/api/v2/incidents', json={'title': 'Incidente legítimo', 'severity': 'P3'})
        assert r.status_code in (200, 201)

    def test_viewer_sigue_pudiendo_leer_los_suyos(self, viewer):
        c, _ = viewer
        assert c.get('/api/v2/incidents').status_code == 200


# ------------------------------------------------------------------ CRIT-01

class TestDeepAnalysisSessionIdor:
    BODY = {'ioc': '1.1.1.1', 'type': 'ip'}

    def _foreign_session(self, db_session, owner):
        s = InvestigationSession(user_id=owner.id, status='active', title='Privada')
        db_session.session.add(s)
        db_session.session.commit()
        return s.id

    def test_senior_no_puede_usar_sesion_ajena(self, app, db_session, senior, other_user):
        c, _ = senior
        sid = self._foreign_session(db_session, other_user)
        with patch('app.routes.deep_analysis_routes.get_deep_service') as svc:
            r = c.post('/api/v2/deep/analyze', json={**self.BODY, 'session_id': sid})
        assert r.status_code == 403
        svc.return_value.deep_analyze.assert_not_called()      # nunca llegó al servicio

    def test_intento_queda_auditado(self, app, db_session, senior, other_user):
        c, _ = senior
        sid = self._foreign_session(db_session, other_user)
        with patch('app.routes.deep_analysis_routes.get_deep_service'):
            c.post('/api/v2/deep/analyze', json={**self.BODY, 'session_id': sid})
        ev = AuditEvent.query.filter_by(action='unauthorized_access', resource_type='session',
                                        resource_id=sid).first()
        assert ev is not None and ev.success is False

    def test_sesion_inexistente_404(self, senior):
        c, _ = senior
        with patch('app.routes.deep_analysis_routes.get_deep_service') as svc:
            r = c.post('/api/v2/deep/analyze', json={**self.BODY, 'session_id': 99999999})
        assert r.status_code == 404
        svc.return_value.deep_analyze.assert_not_called()

    @pytest.mark.parametrize('bad', ['5', 5.5, True, [1], {'a': 1}])
    def test_session_id_de_tipo_invalido_400(self, senior, bad):
        c, _ = senior
        with patch('app.routes.deep_analysis_routes.get_deep_service') as svc:
            r = c.post('/api/v2/deep/analyze', json={**self.BODY, 'session_id': bad})
        assert r.status_code == 400
        svc.return_value.deep_analyze.assert_not_called()

    def test_sesion_propia_ok(self, app, db_session, senior):
        c, user = senior
        sid = self._foreign_session(db_session, user)
        with patch('app.routes.deep_analysis_routes.get_deep_service') as svc:
            svc.return_value.deep_analyze.return_value = {'modules_executed': [], 'processing_time': 0}
            r = c.post('/api/v2/deep/analyze', json={**self.BODY, 'session_id': sid})
        assert r.status_code == 200
        svc.return_value.deep_analyze.assert_called_once()

    def test_admin_puede_usar_cualquier_sesion(self, app, db_session, admin_client, other_user):
        sid = self._foreign_session(db_session, other_user)
        with patch('app.routes.deep_analysis_routes.get_deep_service') as svc:
            svc.return_value.deep_analyze.return_value = {'modules_executed': [], 'processing_time': 0}
            r = admin_client.post('/api/v2/deep/analyze', json={**self.BODY, 'session_id': sid})
        assert r.status_code == 200

    def test_sin_session_id_sigue_funcionando(self, senior):
        c, _ = senior
        with patch('app.routes.deep_analysis_routes.get_deep_service') as svc:
            svc.return_value.deep_analyze.return_value = {'modules_executed': [], 'processing_time': 0}
            assert c.post('/api/v2/deep/analyze', json=self.BODY).status_code == 200


# ------------------------------------------------------------------ CRIT-02

class TestChatCannotBypassDeepRbac:
    MSG = 'haz un análisis profundo de 185.220.101.34'

    def _chat(self, app, user_id):
        from app.services.llm_orchestrator import LLMOrchestrator
        orch = LLMOrchestrator()
        fake_llm = MagicMock(provider='deepseek')
        deep = MagicMock()
        deep.deep_analyze.return_value = {'modules_executed': [], 'processing_time': 0}
        with patch.object(orch, '_initialize_clients'), \
             patch.object(orch, '_get_available_llm', return_value=fake_llm), \
             patch.object(orch, '_call_llm', return_value={'intent_type': 'general_question'}), \
             patch.object(LLMOrchestrator, 'deep_analysis_service', new=deep):
            return orch.chat_analysis(self.MSG, user_id=user_id), deep

    def test_viewer_rechazado_sin_gastar_apis(self, app, db_session, viewer):
        _, user = viewer
        res, deep = self._chat(app, user.id)
        deep.deep_analyze.assert_not_called()
        assert res['deep_analysis'] is False
        assert 'senior_analyst' in res['response']

    def test_analyst_rechazado(self, app, db_session, analyst_user):
        res, deep = self._chat(app, analyst_user.id)
        deep.deep_analyze.assert_not_called()
        assert res['deep_analysis'] is False

    def test_senior_permitido(self, app, db_session, senior):
        _, user = senior
        res, deep = self._chat(app, user.id)
        deep.deep_analyze.assert_called_once()
        assert res['deep_analysis'] is True

    def test_admin_permitido(self, app, db_session, admin_user):
        res, deep = self._chat(app, admin_user.id)
        deep.deep_analyze.assert_called_once()

    def test_usuario_inactivo_rechazado(self, app, db_session, senior):
        _, user = senior
        user.is_active = False
        db_session.session.commit()
        res, deep = self._chat(app, user.id)
        deep.deep_analyze.assert_not_called()

    def test_sin_user_id_rechazado(self, app, db_session):
        res, deep = self._chat(app, None)
        deep.deep_analyze.assert_not_called()

    def test_rechazo_queda_auditado(self, app, db_session, viewer):
        _, user = viewer
        before = AuditEvent.query.filter_by(action='rbac_denied', resource_type='deep_analysis').count()
        self._chat(app, user.id)
        after = AuditEvent.query.filter_by(action='rbac_denied', resource_type='deep_analysis').count()
        assert after == before + 1


# ------------------------------------------------------------------ CRIT-04

class TestSearchIsolation:
    """Se asierta sobre los contadores 'IOCs (N)' y 'Análisis (N)' de search.html:
    el valor buscado se repite en otras partes de la página y no sirve como señal."""

    @staticmethod
    def _counts(resp):
        import re
        html = resp.get_data(as_text=True)
        iocs = int(re.search(r'IOCs \((\d+)\)', html).group(1))
        analyses = int(re.search(r'Análisis \((\d+)\)', html).group(1))
        return iocs, analyses

    def _make(self, db_session, value, user=None, level='ALTO'):
        ioc = IOC(value=value, ioc_type='ip')
        db_session.session.add(ioc)
        db_session.session.commit()
        if user is not None:
            db_session.session.add(IOCAnalysis(ioc_id=ioc.id, user_id=user.id, confidence_score=70,
                                               risk_level=level, sources_used=['virustotal']))
            db_session.session.commit()
        return ioc

    def test_analyst_no_ve_analisis_ni_iocs_de_otros(self, app, db_session, analyst_client, other_user):
        self._make(db_session, '203.0.113.77', other_user)
        r = analyst_client.get('/search?q=203.0.113.77')
        assert r.status_code == 200
        assert self._counts(r) == (0, 0)

    def test_analyst_si_ve_lo_propio(self, app, db_session, analyst_client, analyst_user):
        self._make(db_session, '203.0.113.88', analyst_user, 'CRÍTICO')
        r = analyst_client.get('/search?q=203.0.113.88')
        assert self._counts(r) == (1, 1)

    def test_admin_ve_todo(self, app, db_session, admin_client, other_user):
        self._make(db_session, '203.0.113.99', other_user)
        r = admin_client.get('/search?q=203.0.113.99')
        assert self._counts(r) == (1, 1)

    def test_ioc_sin_analisis_propio_no_aparece_para_analyst(self, app, db_session, analyst_client):
        self._make(db_session, '198.51.100.5')           # IOC global sin análisis de nadie
        r = analyst_client.get('/search?q=198.51.100.5')
        assert self._counts(r) == (0, 0)

    def test_mezcla_solo_devuelve_lo_propio(self, app, db_session, analyst_client, analyst_user, other_user):
        ioc = self._make(db_session, '192.0.2.10', analyst_user)
        db_session.session.add(IOCAnalysis(ioc_id=ioc.id, user_id=other_user.id, confidence_score=10,
                                           risk_level='BAJO', sources_used=['otx']))
        db_session.session.commit()
        r = analyst_client.get('/search?q=192.0.2.10')
        assert self._counts(r) == (1, 1)                  # el IOC compartido, pero solo SU análisis
