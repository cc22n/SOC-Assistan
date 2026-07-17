"""
Tests de Rutas de Incidentes — T3A-03
Cubre: CRUD, ownership 403/404, ticket_id único, timeline, notas, stats
"""
import pytest
import json

BASE = '/api/v2/incidents'
HEADERS = {'Content-Type': 'application/json'}


# ==============================================================================
# HELPERS
# ==============================================================================

def post_json(client, url, data):
    return client.post(url, data=json.dumps(data), headers=HEADERS)


def put_json(client, url, data):
    return client.put(url, data=json.dumps(data), headers=HEADERS)


def create_incident(client, title='Test Incident', severity='P3'):
    return post_json(client, BASE, {'title': title, 'severity': severity})


# ==============================================================================
# AUTENTICACIÓN REQUERIDA
# ==============================================================================

class TestAuth:

    def test_list_incidents_requires_login(self, client):
        """Sin autenticar → 401 o redirect."""
        resp = client.get(BASE)
        assert resp.status_code in (401, 302)

    def test_create_incident_requires_login(self, client):
        """Sin autenticar → 401 o redirect."""
        resp = post_json(client, BASE, {'title': 'test'})
        assert resp.status_code in (401, 302)

    def test_get_incident_requires_login(self, client):
        resp = client.get(f'{BASE}/999')
        assert resp.status_code in (401, 302)


# ==============================================================================
# CREAR INCIDENTE
# ==============================================================================

class TestCreateIncident:

    def test_create_minimal(self, analyst_client):
        """Crea incidente con solo titulo → 201 con ticket_id."""
        resp = create_incident(analyst_client, title='Actividad sospechosa')
        assert resp.status_code == 201
        data = resp.get_json()
        assert data['success'] is True
        assert 'SOC-' in data['incident']['ticket_id']

    def test_create_full_incident(self, analyst_client):
        """Crea incidente con todos los campos → 201."""
        resp = post_json(analyst_client, BASE, {
            'title': 'Incidente P1',
            'description': 'Descripción completa',
            'severity': 'P1',
        })
        assert resp.status_code == 201
        inc = resp.get_json()['incident']
        assert inc['severity'] == 'P1'
        assert inc['status'] == 'open'

    def test_create_without_title_returns_400(self, analyst_client):
        """Sin titulo → 400."""
        resp = post_json(analyst_client, BASE, {'severity': 'P2'})
        assert resp.status_code == 400

    def test_create_without_json_returns_400(self, analyst_client):
        """Sin Content-Type JSON → 400."""
        resp = analyst_client.post(BASE, data='titulo=test')
        assert resp.status_code == 400

    def test_create_invalid_severity_returns_400(self, analyst_client):
        """Severidad no válida → 400."""
        resp = post_json(analyst_client, BASE, {
            'title': 'Test',
            'severity': 'CRITICAL',
        })
        assert resp.status_code == 400

    def test_ticket_id_is_unique(self, analyst_client):
        """Dos incidentes creados seguidos tienen ticket_ids distintos."""
        r1 = create_incident(analyst_client, title='Inc 1')
        r2 = create_incident(analyst_client, title='Inc 2')
        assert r1.status_code == 201
        assert r2.status_code == 201
        t1 = r1.get_json()['incident']['ticket_id']
        t2 = r2.get_json()['incident']['ticket_id']
        assert t1 != t2

    def test_create_adds_timeline_event(self, analyst_client):
        """Crear incidente agrega evento 'created' en timeline."""
        resp = create_incident(analyst_client)
        assert resp.status_code == 201
        timeline = resp.get_json()['incident']['timeline']
        assert any(e['type'] == 'created' for e in timeline)

    def test_create_sets_created_by(self, analyst_client, analyst_user):
        """Campo created_by queda seteado al usuario autenticado."""
        resp = create_incident(analyst_client)
        inc = resp.get_json()['incident']
        assert inc['created_by'] == analyst_user.username


# ==============================================================================
# LISTAR INCIDENTES
# ==============================================================================

class TestListIncidents:

    def test_list_returns_success(self, analyst_client, sample_incident):
        resp = analyst_client.get(BASE)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert isinstance(data['incidents'], list)

    def test_list_filter_by_status(self, analyst_client, sample_incident):
        resp = analyst_client.get(f'{BASE}?status=open')
        assert resp.status_code == 200
        for inc in resp.get_json()['incidents']:
            assert inc['status'] == 'open'

    def test_list_filter_by_severity(self, analyst_client, sample_incident):
        resp = analyst_client.get(f'{BASE}?severity=P2')
        assert resp.status_code == 200
        for inc in resp.get_json()['incidents']:
            assert inc['severity'] == 'P2'

    def test_list_my_only(self, analyst_client, sample_incident):
        """?my_only=true devuelve solo los del usuario actual."""
        resp = analyst_client.get(f'{BASE}?my_only=true')
        assert resp.status_code == 200


# ==============================================================================
# DETALLE DE INCIDENTE
# ==============================================================================

class TestGetIncident:

    def test_get_own_incident(self, analyst_client, sample_incident):
        resp = analyst_client.get(f'{BASE}/{sample_incident.id}')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['incident']['id'] == sample_incident.id

    def test_get_nonexistent_returns_404(self, analyst_client):
        resp = analyst_client.get(f'{BASE}/99999')
        assert resp.status_code == 404

    def test_idor_other_user_cannot_read(self, other_client, sample_incident):
        """Otro analista no puede leer el incidente de otro usuario → 403."""
        resp = other_client.get(f'{BASE}/{sample_incident.id}')
        assert resp.status_code == 403

    def test_admin_can_read_any_incident(self, admin_client, sample_incident):
        """Admin puede leer cualquier incidente."""
        resp = admin_client.get(f'{BASE}/{sample_incident.id}')
        assert resp.status_code == 200


# ==============================================================================
# ACTUALIZAR INCIDENTE
# ==============================================================================

class TestUpdateIncident:

    def test_update_title(self, analyst_client, sample_incident):
        resp = put_json(analyst_client, f'{BASE}/{sample_incident.id}', {
            'title': 'Nuevo título actualizado'
        })
        assert resp.status_code == 200
        assert resp.get_json()['incident']['title'] == 'Nuevo título actualizado'

    def test_update_severity(self, analyst_client, sample_incident):
        resp = put_json(analyst_client, f'{BASE}/{sample_incident.id}', {
            'severity': 'P1'
        })
        assert resp.status_code == 200
        assert resp.get_json()['incident']['severity'] == 'P1'

    def test_update_nonexistent_returns_404(self, analyst_client):
        resp = put_json(analyst_client, f'{BASE}/99999', {'title': 'X'})
        assert resp.status_code == 404

    def test_idor_other_user_cannot_update(self, other_client, sample_incident):
        """Otro analista no puede actualizar el incidente de otro → 403."""
        resp = put_json(other_client, f'{BASE}/{sample_incident.id}', {
            'title': 'Hacked title'
        })
        assert resp.status_code == 403

    def test_update_adds_timeline_event(self, analyst_client, sample_incident):
        """Actualizar un campo agrega evento 'updated' en timeline."""
        put_json(analyst_client, f'{BASE}/{sample_incident.id}', {'title': 'Cambiado'})
        resp = analyst_client.get(f'{BASE}/{sample_incident.id}')
        timeline = resp.get_json()['incident']['timeline']
        assert any(e['type'] == 'updated' for e in timeline)


# ==============================================================================
# CAMBIAR ESTADO
# ==============================================================================

class TestChangeStatus:

    def test_change_status_to_investigating(self, analyst_client, sample_incident):
        resp = put_json(analyst_client, f'{BASE}/{sample_incident.id}/status', {
            'status': 'investigating',
            'reason': 'Iniciando análisis'
        })
        assert resp.status_code == 200
        assert resp.get_json()['incident']['status'] == 'investigating'

    def test_change_status_resolved_sets_resolved_at(self, analyst_client, sample_incident):
        resp = put_json(analyst_client, f'{BASE}/{sample_incident.id}/status', {
            'status': 'resolved'
        })
        assert resp.status_code == 200
        assert resp.get_json()['incident']['resolved_at'] is not None

    def test_invalid_status_returns_400(self, analyst_client, sample_incident):
        resp = put_json(analyst_client, f'{BASE}/{sample_incident.id}/status', {
            'status': 'INVALID'
        })
        assert resp.status_code == 400

    def test_idor_other_user_cannot_change_status(self, other_client, sample_incident):
        resp = put_json(other_client, f'{BASE}/{sample_incident.id}/status', {
            'status': 'closed'
        })
        assert resp.status_code == 403


# ==============================================================================
# NOTAS EN TIMELINE
# ==============================================================================

class TestAddNote:

    def test_add_note_success(self, analyst_client, sample_incident):
        resp = post_json(analyst_client, f'{BASE}/{sample_incident.id}/notes', {
            'content': 'Confirmado: el IOC está activo en producción.',
            'type': 'finding'
        })
        assert resp.status_code == 200
        timeline = resp.get_json()['timeline']
        assert any(e['type'] == 'finding' for e in timeline)

    def test_add_note_empty_content_returns_400(self, analyst_client, sample_incident):
        resp = post_json(analyst_client, f'{BASE}/{sample_incident.id}/notes', {
            'content': ''
        })
        assert resp.status_code == 400

    def test_idor_other_user_cannot_add_note(self, other_client, sample_incident):
        resp = post_json(other_client, f'{BASE}/{sample_incident.id}/notes', {
            'content': 'Nota no autorizada'
        })
        assert resp.status_code == 403


# ==============================================================================
# VINCULAR IOCs
# ==============================================================================

class TestLinkIocs:

    def test_link_iocs_invalid_role_returns_400(self, analyst_client, sample_incident, sample_ioc):
        """role fuera del enum permitido (primary/related/context) → 400."""
        resp = post_json(analyst_client, f'{BASE}/{sample_incident.id}/iocs', {
            'ioc_ids': [sample_ioc.id],
            'role': 'admin'
        })
        assert resp.status_code == 400


# ==============================================================================
# ESTADÍSTICAS
# ==============================================================================

class TestStats:

    def test_stats_returns_counts(self, analyst_client, sample_incident):
        resp = analyst_client.get(f'{BASE}/stats')
        assert resp.status_code == 200
        stats = resp.get_json()['stats']
        assert 'total' in stats
        assert 'open' in stats
        assert 'by_severity' in stats
        assert stats['total'] >= 1
