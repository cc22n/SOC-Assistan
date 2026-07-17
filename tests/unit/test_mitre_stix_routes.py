"""
Tests de IDOR en exportación STIX — app/routes/mitre_stix_routes.py

Los endpoints export_analysis_stix y export_incident_stix requieren
@require_role('senior_analyst') pero antes del fix NO verificaban
propiedad/visibilidad del recurso: un senior_analyst podía exportar el
análisis o incidente de otro usuario adivinando IDs secuenciales (IDOR).

Cubre:
- export_analysis_stix: 403 para no-propietario, 200 para propietario y admin
- export_incident_stix: 403 para no-visible, 200 para visible (creador) y admin
- 404 cuando el recurso no existe
"""
import pytest

BASE = '/api/v2/stix'


# ==============================================================================
# FIXTURES LOCALES
#
# Los endpoints requieren rol 'senior_analyst' o superior (RBAC vía
# @require_role). Los fixtures compartidos de conftest.py (analyst_user /
# other_user / analyst_client / other_client) tienen role='analyst', que es
# INSUFICIENTE para pasar el RBAC — usarlos haría que el test reciba 403 por
# falta de rol, no por el check de IDOR que queremos probar. Por eso se
# definen aquí usuarios propios con role='senior_analyst', siguiendo el mismo
# patrón que conftest.py usa para admin_user/analyst_user/other_user.
# ==============================================================================

def _authenticated_client(app, user):
    c = app.test_client()
    with c.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True
    return c


@pytest.fixture(scope='function')
def senior_user(app, db_session):
    """Usuario con role='senior_analyst' — propietario de los recursos de prueba."""
    from app.models.ioc import User

    user = User(
        username='test_senior',
        email='senior@soc-test.local',
        role='senior_analyst',
        is_active=True,
    )
    user.set_password('SeniorPass123!')
    db_session.session.add(user)
    db_session.session.commit()
    db_session.session.refresh(user)
    return user


@pytest.fixture(scope='function')
def senior_other_user(app, db_session):
    """Segundo senior_analyst — usado para verificar aislamiento (IDOR)."""
    from app.models.ioc import User

    user = User(
        username='test_senior_other',
        email='senior-other@soc-test.local',
        role='senior_analyst',
        is_active=True,
    )
    user.set_password('SeniorOtherPass123!')
    db_session.session.add(user)
    db_session.session.commit()
    db_session.session.refresh(user)
    return user


@pytest.fixture(scope='function')
def senior_client(app, db_session, senior_user):
    with _authenticated_client(app, senior_user) as c:
        yield c


@pytest.fixture(scope='function')
def senior_other_client(app, db_session, senior_other_user):
    with _authenticated_client(app, senior_other_user) as c:
        yield c


@pytest.fixture(scope='function')
def senior_analysis(app, db_session, sample_ioc, senior_user):
    """IOCAnalysis propiedad de senior_user."""
    from app.models.ioc import IOCAnalysis

    analysis = IOCAnalysis(
        ioc_id=sample_ioc.id,
        user_id=senior_user.id,
        confidence_score=75,
        risk_level='ALTO',
        recommendation='Bloquear en firewall perimetral.',
        sources_used=['virustotal'],
        virustotal_data={'malicious': 10, 'suspicious': 1},
    )
    db_session.session.add(analysis)
    db_session.session.commit()
    db_session.session.refresh(analysis)
    return analysis


@pytest.fixture(scope='function')
def senior_incident(app, db_session, senior_user):
    """Incident creado por senior_user."""
    from app.models.ioc import Incident

    incident = Incident(
        ticket_id='SOC-TEST-STIX-001',
        title='Incidente de prueba para export STIX',
        description='Detección de tráfico hacia IP conocida como C2.',
        severity='P2',
        status='open',
        created_by=senior_user.id,
    )
    db_session.session.add(incident)
    db_session.session.commit()
    db_session.session.refresh(incident)
    return incident


# ==============================================================================
# AUTENTICACIÓN / RBAC REQUERIDOS
# ==============================================================================

class TestAuthAndRbac:

    def test_export_analysis_requires_login(self, client, senior_analysis):
        resp = client.get(f'{BASE}/analysis/{senior_analysis.id}')
        assert resp.status_code in (401, 302)

    def test_export_incident_requires_login(self, client, senior_incident):
        resp = client.get(f'{BASE}/incident/{senior_incident.id}')
        assert resp.status_code in (401, 302)

    def test_export_analysis_requires_senior_role(self, analyst_client, senior_analysis):
        """Un 'analyst' (por debajo de senior_analyst) recibe 403 por RBAC."""
        resp = analyst_client.get(f'{BASE}/analysis/{senior_analysis.id}')
        assert resp.status_code == 403

    def test_export_incident_requires_senior_role(self, analyst_client, senior_incident):
        resp = analyst_client.get(f'{BASE}/incident/{senior_incident.id}')
        assert resp.status_code == 403


# ==============================================================================
# IDOR — EXPORT ANALYSIS STIX
# ==============================================================================

class TestExportAnalysisStixIdor:

    def test_idor_non_owner_senior_analyst_gets_403(self, senior_other_client, senior_analysis):
        """Un senior_analyst que NO es dueño del análisis → 403, no el bundle."""
        resp = senior_other_client.get(f'{BASE}/analysis/{senior_analysis.id}')
        assert resp.status_code == 403

    def test_owner_gets_200(self, senior_client, senior_analysis):
        resp = senior_client.get(f'{BASE}/analysis/{senior_analysis.id}')
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['type'] == 'bundle'

    def test_admin_gets_200_for_others_analysis(self, admin_client, senior_analysis):
        resp = admin_client.get(f'{BASE}/analysis/{senior_analysis.id}')
        assert resp.status_code == 200

    def test_nonexistent_analysis_returns_404(self, senior_client):
        resp = senior_client.get(f'{BASE}/analysis/999999')
        assert resp.status_code == 404


# ==============================================================================
# IDOR — EXPORT INCIDENT STIX
# ==============================================================================

class TestExportIncidentStixIdor:

    def test_idor_non_visible_senior_analyst_gets_403(self, senior_other_client, senior_incident):
        """Un senior_analyst que ni creó ni tiene asignado el incidente → 403."""
        resp = senior_other_client.get(f'{BASE}/incident/{senior_incident.id}')
        assert resp.status_code == 403

    def test_creator_gets_200(self, senior_client, senior_incident):
        resp = senior_client.get(f'{BASE}/incident/{senior_incident.id}')
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['type'] == 'bundle'

    def test_assigned_user_gets_200(self, app, db_session, senior_other_client,
                                     senior_incident, senior_other_user):
        """El usuario asignado al incidente también puede exportarlo (is_visible_to)."""
        senior_incident.assigned_to = senior_other_user.id
        db_session.session.commit()

        resp = senior_other_client.get(f'{BASE}/incident/{senior_incident.id}')
        assert resp.status_code == 200

    def test_admin_gets_200_for_others_incident(self, admin_client, senior_incident):
        resp = admin_client.get(f'{BASE}/incident/{senior_incident.id}')
        assert resp.status_code == 200

    def test_nonexistent_incident_returns_404(self, senior_client):
        resp = senior_client.get(f'{BASE}/incident/999999')
        assert resp.status_code == 404
