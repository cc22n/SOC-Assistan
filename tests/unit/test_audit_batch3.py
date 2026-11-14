"""
Regresión de ALTO-06, ALTO-02, ALTO-14 y ALTO-15 (full-audit-report.md, verificados abiertos
el 2026-11-13):
  ALTO-06  commits prematuros en servicios rompían la atomicidad
  ALTO-02  unittest.mock importado en codigo de produccion
  ALTO-14  severidades del esquema Pydantic distintas de las de las rutas (P1-P4)
  ALTO-15  incidentes sin maquina de estados + resolved_at no se reseteaba al reabrir
"""
import ast
import itertools
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from app import db
from app.models.ioc import Incident, IOCAnalysis, InvalidStatusTransition
from app.models.session import SessionIOC
from app.services.session_manager import SessionManager, session_manager

ROOT = Path(__file__).resolve().parents[2]
HEADERS = {'Content-Type': 'application/json'}


def put_json(client, url, data):
    return client.put(url, data=json.dumps(data), headers=HEADERS)


# =============================================================================== ALTO-06

class TestAddIocToSessionTransaccion:
    def _setup(self, analyst_user, sample_ioc):
        session, _ = session_manager.get_or_create_session(analyst_user.id)
        return session

    def test_commit_false_no_confirma_y_rollback_lo_deshace(self, app, db_session, analyst_user, sample_ioc):
        with app.app_context():
            s = self._setup(analyst_user, sample_ioc)
            sid, iid = s.id, sample_ioc.id
            session_manager.add_ioc_to_session(sid, iid, commit=False)
            assert SessionIOC.query.filter_by(session_id=sid, ioc_id=iid).count() == 1   # visible (flush)
            db_session.session.rollback()
            assert SessionIOC.query.filter_by(session_id=sid, ioc_id=iid).count() == 0   # nada se confirmó
            assert db_session.session.get(type(s), sid).total_iocs == 0

    def test_commit_true_por_defecto_sigue_confirmando(self, app, db_session, analyst_user, sample_ioc):
        with app.app_context():
            s = self._setup(analyst_user, sample_ioc)
            sid, iid = s.id, sample_ioc.id
            session_manager.add_ioc_to_session(sid, iid)
            db_session.session.rollback()
            assert SessionIOC.query.filter_by(session_id=sid, ioc_id=iid).count() == 1

    def test_actualizar_vinculo_existente_con_commit_false(self, app, db_session, analyst_user,
                                                           sample_ioc, sample_analysis):
        with app.app_context():
            s = self._setup(analyst_user, sample_ioc)
            sid, iid = s.id, sample_ioc.id
            session_manager.add_ioc_to_session(sid, iid)                       # confirmado
            session_manager.add_ioc_to_session(sid, iid, analysis_id=sample_analysis.id,
                                               notes='nota', commit=False)      # sin confirmar
            db_session.session.rollback()
            link = SessionIOC.query.filter_by(session_id=sid, ioc_id=iid).one()
            assert link.analysis_id is None and link.analyst_notes is None     # se revirtió solo lo nuevo


class TestRutaAnalisisAtomica:
    RESULT = {
        'confidence_score': 75, 'risk_level': 'ALTO',
        'api_results': {'virustotal': {'malicious': 30}}, 'llm_analysis': {'recommendations': ['x']},
        'sources_used': ['virustotal'], 'mitre_techniques': [], 'processing_time': 1.0,
        'timestamp': '2026-11-13T00:00:00',
    }

    def _post(self, client, session_id, **patches):
        with patch('app.routes.api_v2_routes.get_orchestrator') as orch, \
                patch('app.services.ioc_cache.get_cached_analysis', return_value=None):
            orch.return_value.analyze_with_intelligence.return_value = self.RESULT
            return client.post('/api/v2/analyze/enhanced', data=json.dumps(
                {'ioc': '203.0.113.50', 'type': 'ip', 'session_id': session_id, 'use_llm_planning': False}),
                headers=HEADERS)

    def test_la_ruta_vincula_con_commit_false(self, app, db_session, analyst_client, analyst_user):
        with app.app_context():
            s, _ = session_manager.get_or_create_session(analyst_user.id)
            sid = s.id
        with patch.object(SessionManager, 'add_ioc_to_session', autospec=True,
                          side_effect=SessionManager.add_ioc_to_session) as spy:
            r = self._post(analyst_client, sid)
        assert r.status_code == 200
        assert spy.call_args.kwargs['commit'] is False      # la ruta es dueña de la transacción

    def test_si_falla_la_vinculacion_se_conserva_el_analisis(self, app, db_session, analyst_client, analyst_user):
        with app.app_context():
            s, _ = session_manager.get_or_create_session(analyst_user.id)
            sid = s.id
        with patch.object(SessionManager, 'add_ioc_to_session', side_effect=RuntimeError('boom')):
            r = self._post(analyst_client, sid)
        assert r.status_code == 200                           # el SAVEPOINT aisló el fallo
        assert IOCAnalysis.query.count() == 1                 # el análisis NO se perdió
        assert SessionIOC.query.count() == 0


# =============================================================================== ALTO-02

class TestSinMocksEnProduccion:
    def test_ningun_modulo_de_app_importa_unittest_mock(self):
        ofensores = []
        for path in (ROOT / 'app').rglob('*.py'):
            tree = ast.parse(path.read_text(encoding='utf-8'))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    mods = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    mods = [node.module or '']
                else:
                    continue
                if any(m == 'unittest' or m.startswith('unittest.') or m == 'mock' for m in mods):
                    ofensores.append(f'{path.relative_to(ROOT)}:{node.lineno}')
        assert not ofensores, f'unittest.mock en produccion: {ofensores}'

    def test_no_hay_isinstance_mock_en_runtime(self):
        for rel in ('app/utils/http_client.py', 'app/services/deep_analysis_service.py'):
            src = (ROOT / rel).read_text(encoding='utf-8')
            assert 'Mock' not in src and '_mock_' not in src, rel

    def test_http_get_y_post_usan_la_sesion_con_pooling(self, monkeypatch):
        from app.utils import http_client
        session = MagicMock()
        monkeypatch.setattr(http_client, 'get_http_session', lambda *a, **k: session)
        http_client.http_get('http://x.test/a', params={'q': 1}, timeout=3)
        http_client.http_post('http://x.test/b', json={'k': 1}, timeout=4)
        session.get.assert_called_once_with('http://x.test/a', params={'q': 1}, timeout=3)
        session.post.assert_called_once_with('http://x.test/b', json={'k': 1}, timeout=4)

    def test_deep_analysis_call_llm_usa_generate(self, app):
        with app.app_context():
            from app.services.deep_analysis_service import DeepAnalysisService
            svc = DeepAnalysisService()
            svc._llm_service = MagicMock()
            svc._llm_service.generate.return_value = {'analysis': 'ok'}
            assert svc._call_llm('prompt') == {'analysis': 'ok'}
            svc._llm_service.generate.assert_called_once_with('prompt')

    def test_deep_analysis_sin_generate_devuelve_error(self, app):
        with app.app_context():
            from app.services.deep_analysis_service import DeepAnalysisService
            svc = DeepAnalysisService()
            svc._llm_service = SimpleNamespace()            # sin generate()
            assert svc._call_llm('p') == {'error': 'No LLM method available'}


# =============================================================================== ALTO-14

class TestSeveridadesUnificadas:
    def test_esquema_coincide_con_el_modelo(self):
        from app.schemas.api import IncidentSeverity, IncidentStatus
        assert tuple(e.value for e in IncidentSeverity) == Incident.VALID_SEVERITIES
        assert tuple(e.value for e in IncidentStatus) == Incident.VALID_STATUSES

    def test_openapi_coincide_con_el_modelo(self, analyst_client):
        r = analyst_client.get('/api/docs/openapi.json')
        assert r.status_code == 200
        spec = r.get_json()
        sev_enums = []

        def walk(o):
            if isinstance(o, dict):
                if o.get('enum') and 'P1' in o['enum']:
                    sev_enums.append(tuple(o['enum']))
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)
        walk(spec)
        assert sev_enums and all(e == Incident.VALID_SEVERITIES for e in sev_enums), sev_enums

    @pytest.mark.parametrize('entrada,esperado', [
        ('P1', 'P1'), ('p2', 'P2'), ('critical', 'P1'), ('HIGH', 'P2'), ('medium', 'P3'),
        ('low', 'P4'), ('info', 'P4'), ('Crítico', 'P1'), ('alto', 'P2'),
    ])
    def test_pydantic_normaliza_nombres_antiguos(self, entrada, esperado):
        from app.schemas.api import IncidentCreateRequest, IncidentUpdateRequest
        assert IncidentCreateRequest(title='abc', severity=entrada).severity.value == esperado
        assert IncidentUpdateRequest(severity=entrada).severity.value == esperado

    @pytest.mark.parametrize('malo', ['urgent', 'P5', 'P0', '', 5, None])
    def test_pydantic_rechaza_valores_desconocidos(self, malo):
        from pydantic import ValidationError
        from app.schemas.api import IncidentCreateRequest
        with pytest.raises(ValidationError):
            IncidentCreateRequest(title='abc', severity=malo)

    def test_default_es_p3(self):
        from app.schemas.api import IncidentCreateRequest
        assert IncidentCreateRequest(title='abc').severity.value == 'P3'

    def test_update_con_severidad_invalida_da_400_y_no_modifica(self, analyst_client, sample_incident, db_session):
        r = put_json(analyst_client, f'/api/v2/incidents/{sample_incident.id}', {'severity': 'critical'})
        assert r.status_code == 400                      # antes: 200 ignorándola en silencio
        db_session.session.refresh(sample_incident)
        assert sample_incident.severity == 'P2'

    def test_update_con_severidad_valida(self, analyst_client, sample_incident, db_session):
        r = put_json(analyst_client, f'/api/v2/incidents/{sample_incident.id}', {'severity': 'P1'})
        assert r.status_code == 200
        assert r.get_json()['incident']['severity'] == 'P1'


# =============================================================================== ALTO-15

ESTADOS = Incident.VALID_STATUSES


def _nuevo(status):
    inc = Incident(ticket_id='T-FSM', title='t', severity='P3', status=status)
    return inc


class TestMaquinaDeEstadosModelo:
    @pytest.mark.parametrize('old,new', list(itertools.product(ESTADOS, ESTADOS)))
    def test_las_16_combinaciones(self, old, new):
        inc = _nuevo(old)
        permitido = new in Incident.STATUS_TRANSITIONS[old]
        if permitido:
            inc.transition_to(new)
            assert inc.status == new
        else:
            with pytest.raises(InvalidStatusTransition) as e:
                inc.transition_to(new)
            assert e.value.allowed == list(Incident.STATUS_TRANSITIONS[old])
            assert inc.status == old                    # un intento inválido no altera el estado

    def test_decisiones_de_negocio_clave(self):
        T = Incident.STATUS_TRANSITIONS
        assert 'closed' not in T['open']                # open -> closed ilógico (reporte ALTO-15)
        assert 'resolved' not in T['closed']            # no se resucita una resolución
        assert 'resolved' in T['open']                  # la resolución inmediata sí se permite
        for e in ESTADOS:
            assert e not in T[e]                        # sin no-ops

    def test_todos_los_destinos_son_estados_validos(self):
        for src, dsts in Incident.STATUS_TRANSITIONS.items():
            assert src in ESTADOS and set(dsts) <= set(ESTADOS)

    def test_resolver_fija_resolved_at(self):
        inc = _nuevo('investigating')
        inc.transition_to('resolved')
        assert inc.resolved_at is not None

    @pytest.mark.parametrize('desde', ['resolved', 'closed'])
    @pytest.mark.parametrize('hacia', ['open', 'investigating'])
    def test_reabrir_limpia_resolved_at(self, desde, hacia):
        from app.utils.time_utils import utcnow
        inc = _nuevo(desde)
        inc.resolved_at = utcnow()
        _, reopened = inc.transition_to(hacia)
        assert reopened is True and inc.resolved_at is None

    def test_cerrar_desde_resuelto_conserva_resolved_at(self):
        inc = _nuevo('investigating')
        inc.transition_to('resolved')
        fecha = inc.resolved_at
        _, reopened = inc.transition_to('closed')
        assert inc.resolved_at == fecha and reopened is False

    def test_estado_none_se_trata_como_open(self):
        inc = _nuevo(None)
        assert inc.allowed_transitions() == list(Incident.STATUS_TRANSITIONS['open'])
        inc.transition_to('investigating')


class TestMaquinaDeEstadosRuta:
    def _cambiar(self, c, inc, status, reason=None):
        body = {'status': status}
        if reason:
            body['reason'] = reason
        return put_json(c, f'/api/v2/incidents/{inc.id}/status', body)

    def test_open_a_closed_da_409_con_permitidos(self, analyst_client, sample_incident, db_session):
        r = self._cambiar(analyst_client, sample_incident, 'closed')
        assert r.status_code == 409
        body = r.get_json()
        assert body['current'] == 'open' and body['allowed'] == ['investigating', 'resolved']
        db_session.session.refresh(sample_incident)
        assert sample_incident.status == 'open'

    def test_mismo_estado_da_409(self, analyst_client, sample_incident):
        assert self._cambiar(analyst_client, sample_incident, 'open').status_code == 409

    def test_ciclo_completo_y_reapertura_resetean_resolved_at(self, analyst_client, sample_incident):
        c = analyst_client
        assert self._cambiar(c, sample_incident, 'investigating').status_code == 200
        r = self._cambiar(c, sample_incident, 'resolved')
        assert r.status_code == 200 and r.get_json()['incident']['resolved_at'] is not None
        r = self._cambiar(c, sample_incident, 'investigating', 'volvió a aparecer')      # reapertura
        inc = r.get_json()['incident']
        assert r.status_code == 200 and inc['resolved_at'] is None                       # MTTR no queda falso
        assert any('[reabierto]' in e['description'] and 'volvió a aparecer' in e['description']
                   for e in inc['timeline'])

    def test_closed_a_resolved_da_409(self, analyst_client, sample_incident):
        c = analyst_client
        for st in ('investigating', 'closed'):
            assert self._cambiar(c, sample_incident, st).status_code == 200
        assert self._cambiar(c, sample_incident, 'resolved').status_code == 409

    def test_el_detalle_expone_allowed_transitions(self, analyst_client, sample_incident):
        inc = analyst_client.get(f'/api/v2/incidents/{sample_incident.id}').get_json()['incident']
        assert inc['allowed_transitions'] == ['investigating', 'resolved']

    def test_estado_invalido_sigue_siendo_400(self, analyst_client, sample_incident):
        assert self._cambiar(analyst_client, sample_incident, 'INVALID').status_code == 400

    def test_viewer_sigue_sin_poder(self, app, db_session, sample_incident):
        from tests.unit.test_authorization_fixes import _client_for
        c, _ = _client_for(app, db_session, 'fsm_viewer', 'viewer')
        assert self._cambiar(c, sample_incident, 'investigating').status_code == 403


class TestUiIncidenteDetalle:
    def test_la_ui_muestra_errores_y_filtra_acciones(self):
        html = (ROOT / 'app' / 'templates' / 'incident_detail.html').read_text(encoding='utf-8')
        assert 'function applyAllowedTransitions' in html
        assert 'allowed_transitions' in html
        assert html.count("showToast(data.error || 'No se pudo cambiar el estado', 'error')") >= 2

    def test_la_fila_de_resolucion_se_oculta_al_reabrir(self):
        """Verificado en Chrome: tras reabrir, la pagina conservaba la fecha de resolucion anterior."""
        html = (ROOT / 'app' / 'templates' / 'incident_detail.html').read_text(encoding='utf-8')
        assert "metaResolvedRow').style.display = 'none'" in html
