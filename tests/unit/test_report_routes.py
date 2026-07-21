"""
Tests unitarios — app/routes/report_routes.py (blueprint 'reports', prefix /api/v2/reports)

Cubre:
- GET  /session/<id>/pdf      — ownership (200 propio, 403 ajeno, 200 admin, 404 inexistente)
- GET  /session/<id>/docx     — mismo patrón de ownership
- GET  /session/<id>/preview  — mismo patrón de ownership + estructura del preview
- POST /analysis/<id>/pdf     — ownership sobre IOCAnalysis.user_id
- GET  /formats                — smoke test, no requiere ownership

No se mockean reportlab/python-docx: la generación es determinística y rápida
para una sesión con 0-1 IOCs, así que se ejercitan las rutas reales.
"""
import pytest

BASE = '/api/v2/reports'


# ==============================================================================
# FIXTURES LOCALES — sesiones de investigación
#
# No existe fixture de InvestigationSession en conftest.py; se crean aquí
# siguiendo el mismo patrón usado en tests/unit/test_deep_analysis.py y
# tests/unit/test_mitre_stix_routes.py (usuarios/fixtures propios cuando se
# necesita una combinación de ownership no cubierta por conftest.py).
# ==============================================================================

@pytest.fixture(scope='function')
def sample_session(app, db_session, analyst_user):
    """Sesión de investigación propiedad de analyst_user.

    highest_risk_level se fija explícitamente: en producción lo mantiene el
    trigger SQL `trigger_session_risk_level` (migrations/add_investigation_sessions.sql),
    que no se aplica en la BD de test (el esquema se crea con db.create_all(),
    ver CLAUDE.md) — sin esto el campo queda NULL y expone un bug real y
    preexistente de generate_docx (cell_value.text = None) no relacionado con
    lo que este archivo cubre.
    """
    from app.models.session import InvestigationSession

    session_obj = InvestigationSession(
        user_id=analyst_user.id,
        title='Sesion de prueba',
        status='active',
        highest_risk_level='ALTO',
    )
    db_session.session.add(session_obj)
    db_session.session.commit()
    db_session.session.refresh(session_obj)
    return session_obj


@pytest.fixture(scope='function')
def sample_session_with_ioc(app, db_session, sample_session, sample_ioc, sample_analysis):
    """Sesión con un IOC vinculado, para probar preview con datos no vacíos."""
    from app.models.session import SessionIOC

    session_ioc = SessionIOC(
        session_id=sample_session.id,
        ioc_id=sample_ioc.id,
        analysis_id=sample_analysis.id,
        role='primary',
    )
    db_session.session.add(session_ioc)
    db_session.session.commit()
    return sample_session


@pytest.fixture(scope='function')
def other_session(app, db_session, other_user):
    """Sesión de investigación propiedad de other_user (para tests de ownership)."""
    from app.models.session import InvestigationSession

    session_obj = InvestigationSession(
        user_id=other_user.id,
        title='Sesion ajena',
        status='active',
    )
    db_session.session.add(session_obj)
    db_session.session.commit()
    db_session.session.refresh(session_obj)
    return session_obj


# ==============================================================================
# GET /session/<id>/pdf
# ==============================================================================

class TestSessionPdf:

    def test_requires_login(self, client, sample_session):
        resp = client.get(f'{BASE}/session/{sample_session.id}/pdf')
        assert resp.status_code in (401, 302)

    def test_owner_gets_200(self, analyst_client, sample_session):
        resp = analyst_client.get(f'{BASE}/session/{sample_session.id}/pdf')
        assert resp.status_code == 200
        assert resp.mimetype == 'application/pdf'

    def test_non_owner_gets_403(self, other_client, sample_session):
        resp = other_client.get(f'{BASE}/session/{sample_session.id}/pdf')
        assert resp.status_code == 403

    def test_admin_gets_200_for_others_session(self, admin_client, sample_session):
        resp = admin_client.get(f'{BASE}/session/{sample_session.id}/pdf')
        assert resp.status_code == 200
        assert resp.mimetype == 'application/pdf'

    def test_nonexistent_session_returns_404(self, analyst_client):
        resp = analyst_client.get(f'{BASE}/session/999999/pdf')
        assert resp.status_code == 404

    def test_with_ioc_data_gets_200(self, analyst_client, sample_session_with_ioc):
        resp = analyst_client.get(
            f'{BASE}/session/{sample_session_with_ioc.id}/pdf?include_api_details=true'
        )
        assert resp.status_code == 200
        assert resp.mimetype == 'application/pdf'


# ==============================================================================
# GET /session/<id>/docx
# ==============================================================================

class TestSessionDocx:

    def test_requires_login(self, client, sample_session):
        resp = client.get(f'{BASE}/session/{sample_session.id}/docx')
        assert resp.status_code in (401, 302)

    def test_owner_gets_200(self, analyst_client, sample_session):
        resp = analyst_client.get(f'{BASE}/session/{sample_session.id}/docx')
        assert resp.status_code == 200
        assert resp.mimetype == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'

    def test_non_owner_gets_403(self, other_client, sample_session):
        resp = other_client.get(f'{BASE}/session/{sample_session.id}/docx')
        assert resp.status_code == 403

    def test_admin_gets_200_for_others_session(self, admin_client, sample_session):
        resp = admin_client.get(f'{BASE}/session/{sample_session.id}/docx')
        assert resp.status_code == 200

    def test_null_highest_risk_level_does_not_crash(self, analyst_client, db_session, analyst_user):
        """Regresión: highest_risk_level=None (sin trigger SQL en test) causaba
        TypeError en python-docx (cell.text = None). Ver fixture sample_session."""
        from app.models.session import InvestigationSession

        session_obj = InvestigationSession(
            user_id=analyst_user.id, title='Sin riesgo aun', status='active',
            highest_risk_level=None,
        )
        db_session.session.add(session_obj)
        db_session.session.commit()

        resp = analyst_client.get(f'{BASE}/session/{session_obj.id}/docx')
        assert resp.status_code == 200

    def test_nonexistent_session_returns_404(self, analyst_client):
        resp = analyst_client.get(f'{BASE}/session/999999/docx')
        assert resp.status_code == 404


# ==============================================================================
# GET /session/<id>/preview
# ==============================================================================

class TestSessionPreview:

    def test_requires_login(self, client, sample_session):
        resp = client.get(f'{BASE}/session/{sample_session.id}/preview')
        assert resp.status_code in (401, 302)

    def test_owner_gets_200(self, analyst_client, sample_session):
        resp = analyst_client.get(f'{BASE}/session/{sample_session.id}/preview')
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['success'] is True
        preview = body['preview']
        assert preview['session']['id'] == sample_session.id
        assert 'statistics' in preview
        assert 'iocs_summary' in preview
        assert preview['available_formats'] == ['pdf', 'docx', 'json', 'markdown']

    def test_non_owner_gets_403(self, other_client, sample_session):
        resp = other_client.get(f'{BASE}/session/{sample_session.id}/preview')
        assert resp.status_code == 403

    def test_admin_gets_200_for_others_session(self, admin_client, sample_session):
        resp = admin_client.get(f'{BASE}/session/{sample_session.id}/preview')
        assert resp.status_code == 200

    def test_nonexistent_session_returns_404(self, analyst_client):
        resp = analyst_client.get(f'{BASE}/session/999999/preview')
        assert resp.status_code == 404

    def test_preview_with_ioc_reflects_statistics(self, analyst_client, sample_session_with_ioc):
        resp = analyst_client.get(f'{BASE}/session/{sample_session_with_ioc.id}/preview')
        assert resp.status_code == 200
        preview = resp.get_json()['preview']
        assert preview['statistics']['total_iocs'] == 1
        assert preview['statistics']['high_count'] == 1  # sample_analysis.risk_level == 'ALTO'
        assert len(preview['iocs_summary']) == 1


# ==============================================================================
# POST /analysis/<id>/pdf
# ==============================================================================

class TestAnalysisPdf:

    def test_requires_login(self, client, sample_analysis):
        resp = client.get(f'{BASE}/analysis/{sample_analysis.id}/pdf')
        assert resp.status_code in (401, 302)

    def test_owner_gets_200(self, analyst_client, sample_analysis):
        resp = analyst_client.get(f'{BASE}/analysis/{sample_analysis.id}/pdf')
        assert resp.status_code == 200
        assert resp.mimetype == 'application/pdf'

    def test_non_owner_gets_403(self, other_client, sample_analysis):
        resp = other_client.get(f'{BASE}/analysis/{sample_analysis.id}/pdf')
        assert resp.status_code == 403

    def test_admin_gets_200_for_others_analysis(self, admin_client, sample_analysis):
        resp = admin_client.get(f'{BASE}/analysis/{sample_analysis.id}/pdf')
        assert resp.status_code == 200

    def test_nonexistent_analysis_returns_404(self, analyst_client):
        resp = analyst_client.get(f'{BASE}/analysis/999999/pdf')
        assert resp.status_code == 404


# ==============================================================================
# GET /formats
# ==============================================================================

class TestAvailableFormats:

    def test_requires_login(self, client):
        resp = client.get(f'{BASE}/formats')
        assert resp.status_code in (401, 302)

    def test_returns_format_list(self, analyst_client):
        resp = analyst_client.get(f'{BASE}/formats')
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['success'] is True
        ids = {f['id'] for f in body['formats']}
        assert ids == {'pdf', 'docx', 'json', 'markdown'}
