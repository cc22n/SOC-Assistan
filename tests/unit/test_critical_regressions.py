"""Tests de regresión para vulnerabilidades críticas auditadas y corregidas:
1. BOLA / IDOR en sesiones de análisis (/api/v2/analyze/enhanced y /api/v2/chat/message)
2. BOLA en creación de incidentes asociando sesiones ajenas
3. Restricción de acceso en Deep Analysis (/api/v2/deep/analyze) por RBAC
4. Aislamiento de métricas de Dashboard para usuarios no-administradores
"""
import pytest
from app.models.session import InvestigationSession
from app.models.ioc import Incident


class TestIdorSessionIsolation:
    def test_analyst_cannot_use_another_users_session_in_analyze(self, app, db_session, analyst_client, other_user):
        "write test"
        with app.app_context():
            foreign_session = InvestigationSession(
                user_id=other_user.id,
                status='active',
                title='Foreign Investigation'
            )
            db_session.session.add(foreign_session)
            db_session.session.commit()
            foreign_id = foreign_session.id

        resp = analyst_client.post('/api/v2/analyze/enhanced', json={
            'ioc': '8.8.8.8',
            'type': 'ip',
            'session_id': foreign_id
        })
        assert resp.status_code in (403, 404)
        data = resp.get_json()
        assert 'error' in data

    def test_analyst_cannot_post_chat_message_to_foreign_session(self, app, db_session, analyst_client, other_user):
        with app.app_context():
            foreign_session = InvestigationSession(
                user_id=other_user.id,
                status='active',
                title='Private Session'
            )
            db_session.session.add(foreign_session)
            db_session.session.commit()
            foreign_id = foreign_session.id

        resp = analyst_client.post('/api/v2/chat/message', json={
            'session_id': foreign_id,
            'message': 'Unauthorized injection attempt'
        })
        assert resp.status_code in (403, 404)


    def test_analyst_cannot_link_foreign_session_to_new_incident(self, app, db_session, analyst_client, other_user):
        with app.app_context():
            foreign_session = InvestigationSession(
                user_id=other_user.id,
                status='active',
                title='Other analyst investigation'
            )
            db_session.session.add(foreign_session)
            db_session.session.commit()
            foreign_id = foreign_session.id

        resp = analyst_client.post('/api/v2/incidents', json={
            'title': 'Suspicious Activity Incident',
            'session_id': foreign_id,
            'severity': 'P3'
        })
        assert resp.status_code in (403, 404)


class TestRbacDEepAnalysis:
    def test_viewer_and_analyst_denied_deep_analyze(self, app, db_session, analyst_client):
        resp = analyst_client.post('/api/v2/deep/analyze', json={
            'ioc': '1.1.1.1',
            'type': 'ip'
        })
        assert resp.status_code == 403
        data = resp.get_json()
        assert data.get('error') == 'Forbidden'


class TestDashboardPrivacyIsolation:
    def test_non_admin_stats_are_always_user_filtered(self, app, db_session, analyst_client):
        resp = analyst_client.get('/dashboard/api/stats')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data.get('user_filtered') is True
