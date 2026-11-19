"""
Matriz de autorización por objeto — DESCUBRE las rutas automáticamente (app.url_map).

Todo endpoint con <int:session_id|incident_id|analysis_id> opera sobre un recurso con DUEÑO. Para cada uno
se prueba que un NO dueño (anónimo, viewer, otro analyst, otro senior_analyst) NUNCA obtiene éxito, y un
control positivo (admin) demuestra que la URL es válida y llega a la lógica (si no, un 404 por URL mal
formada ocultaría una fuga).

Una ruta NUEVA con un parámetro de objeto sin clasificar HACE FALLAR el test `test_toda_ruta_esta_clasificada`:
obliga a decidir su política de acceso antes de poder mergear.
Origen: la auditoría de Gemini afirmó "cero fugas" sin enseñar la matriz; aquí queda comprobable.
"""
import json

import pytest

from app.models.ioc import IOC, IOCAnalysis, Incident, IncidentIOC, User
from app.models.profile import InvestigationProfile
from app.models.feed import TechStackEntry
from app.models.session import InvestigationSession

OWNER_SCOPED = {'session_id', 'incident_id', 'analysis_id', 'profile_id'}   # el recurso tiene dueño: solo él o un admin
GLOBAL_PARAMS = {'ioc_id', 'api_name', 'malware_name', 'technique_id', 'entry_id'}   # recursos/catálogos globales (RBAC por rol)
DENIED = {401, 302, 403, 404}

# cuerpos válidos para llegar a la lógica de autorización (un 400 de validación no debe ocultar nada)
BODIES = {
    ('PUT', '/api/v2/incidents/<int:incident_id>'): {'title': 'cambio no autorizado'},
    ('POST', '/api/v2/incidents/<int:incident_id>/iocs'): {'ioc_ids': [1]},
    ('POST', '/api/v2/incidents/<int:incident_id>/notes'): {'content': 'nota no autorizada'},
    ('PUT', '/api/v2/incidents/<int:incident_id>/status'): {'status': 'investigating'},
    ('PATCH', '/api/v2/sessions/<int:session_id>'): {'title': 'titulo no autorizado'},
    ('PUT', '/api/v2/sessions/<int:session_id>'): {'title': 'titulo no autorizado'},
    ('PUT', '/api/v2/profiles/<int:profile_id>'): {'name': 'renombrado sin permiso'},
}


def _rutas(app):
    """[(regla, metodo)] de todas las rutas con parámetro de objeto."""
    out = []
    for r in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
        if r.endpoint == 'static' or not r.arguments:
            continue
        for m in sorted(r.methods - {'HEAD', 'OPTIONS'}):
            out.append((r.rule, m, frozenset(r.arguments)))
    return out


def _client(app, user):
    c = app.test_client()
    if user is not None:
        with c.session_transaction() as s:
            s['_user_id'] = str(user.id)
            s['_fresh'] = True
    return c


def _usuario(db_session, username, role):
    u = User(username=username, email=f'{username}@soc-test.local', role=role, is_active=True)
    u.password_hash = 'x'      # nunca inician sesión por formulario: evita ~140 ms de scrypt por usuario
    db_session.session.add(u)
    db_session.session.commit()
    return u


@pytest.fixture
def mundo(app, db_session):
    """Un dueño (analyst) con sesión, incidente, análisis e IOC; más los actores que NO son dueños."""
    dueno = _usuario(db_session, 'mx_dueno', 'analyst')
    ioc = IOC(value='185.220.101.34', ioc_type='ip')
    db_session.session.add(ioc)
    db_session.session.commit()
    analisis = IOCAnalysis(ioc_id=ioc.id, user_id=dueno.id, confidence_score=80, risk_level='ALTO',
                           sources_used=['virustotal'], llm_analysis={'executive_summary': 'secreto'})
    sesion = InvestigationSession(user_id=dueno.id, status='active', title='sesion privada')
    incidente = Incident(ticket_id='MX-1', title='incidente privado', severity='P2', status='open',
                         created_by=dueno.id)
    perfil = InvestigationProfile(owner_id=dueno.id, name='perfil privado', ioc_type='ip',
                                  apis=['abuseipdb', 'greynoise'])
    entrada_stack = TechStackEntry(vendor='Cisco', product=None, created_by=dueno.id)     # el stack es GLOBAL: protegido por rol
    db_session.session.add_all([analisis, sesion, incidente, perfil, entrada_stack])
    db_session.session.commit()
    # vínculo incidente<->IOC existente: sin él, el DELETE da un 404 legítimo ("Vínculo no encontrado") que
    # impediría distinguir "no autorizado" de "no existe" y debilitaría la prueba
    db_session.session.add(IncidentIOC(incident_id=incidente.id, ioc_id=ioc.id, role='related'))
    db_session.session.commit()
    return SimpleNamespace_(
        ids={'session_id': sesion.id, 'incident_id': incidente.id, 'analysis_id': analisis.id,
             'profile_id': perfil.id, 'entry_id': entrada_stack.id, 'ioc_id': ioc.id, 'api_name': 'virustotal', 'malware_name': 'Emotet', 'technique_id': 'T1071'},
        dueno=dueno,
        viewer=_usuario(db_session, 'mx_viewer', 'viewer'),
        otro_analyst=_usuario(db_session, 'mx_otro', 'analyst'),
        otro_senior=_usuario(db_session, 'mx_senior', 'senior_analyst'),
        admin=_usuario(db_session, 'mx_admin', 'admin'),
    )


class SimpleNamespace_:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def _url(regla, ids):
    url = regla
    for nombre, valor in ids.items():
        for conv in ('int:', 'string:', ''):
            url = url.replace(f'<{conv}{nombre}>', str(valor))
    return url


def _llamar(client, metodo, regla, ids):
    url = _url(regla, ids)
    kw = {}
    cuerpo = BODIES.get((metodo, regla))
    if cuerpo is not None:
        kw = {'data': json.dumps(cuerpo), 'headers': {'Content-Type': 'application/json'}}
    return getattr(client, metodo.lower())(url, **kw)


class TestClasificacion:
    def test_toda_ruta_esta_clasificada(self, app):
        """Una ruta nueva con parámetro de objeto debe declarar su política aquí (dueño-exclusivo o global)."""
        sin_clasificar = []
        for regla, metodo, args in _rutas(app):
            if not (args & (OWNER_SCOPED | GLOBAL_PARAMS)) or not args <= (OWNER_SCOPED | GLOBAL_PARAMS):
                sin_clasificar.append(f'{metodo} {regla} (parámetros: {sorted(args)})')
        assert not sin_clasificar, ('rutas con parámetros sin clasificar en OWNER_SCOPED/GLOBAL_PARAMS: '
                                    f'{sin_clasificar}')

    def test_se_descubren_suficientes_rutas(self, app):
        propias = [r for r in _rutas(app) if r[2] & OWNER_SCOPED]
        assert len(propias) >= 20, f'solo {len(propias)} rutas dueño-exclusivo: ¿cambió el descubrimiento?'


def _casos():
    """Parametrización resuelta en tiempo de colección (necesita la app): se rellena en conftest-free modo."""
    from app import create_app
    app = create_app('testing')
    return [(r, m) for r, m, a in _rutas(app) if a & OWNER_SCOPED]


CASOS = _casos()
ACTORES = ['anonimo', 'viewer', 'otro_analyst', 'otro_senior']


class TestNoDuenoNuncaTieneExito:
    @pytest.mark.parametrize('actor', ACTORES)
    @pytest.mark.parametrize('regla,metodo', CASOS, ids=[f'{m} {r}' for r, m in CASOS])
    def test_denegado(self, app, mundo, actor, regla, metodo):
        user = None if actor == 'anonimo' else getattr(mundo, actor)
        r = _llamar(_client(app, user), metodo, regla, mundo.ids)
        assert r.status_code in DENIED, (
            f'FUGA o error: {actor} -> {metodo} {_url(regla, mundo.ids)} devolvió {r.status_code} '
            f'(esperado uno de {sorted(DENIED)}). Cuerpo: {r.get_data(as_text=True)[:200]}')

    @pytest.mark.parametrize('regla,metodo', CASOS, ids=[f'{m} {r}' for r, m in CASOS])
    def test_control_positivo_admin_si_llega(self, app, mundo, regla, metodo):
        """Si el admin recibe 403/404/405 la URL del test está mal y la prueba negativa no demostraría nada."""
        r = _llamar(_client(app, mundo.admin), metodo, regla, mundo.ids)
        assert r.status_code not in {401, 302, 403, 404, 405}, (
            f'el admin no llega a {metodo} {_url(regla, mundo.ids)}: {r.status_code} '
            f'{r.get_data(as_text=True)[:150]}')


class TestRecursosGlobalesPorRol:
    """ioc/api/mitre no tienen dueño: se protegen por rol. El anónimo nunca entra y el viewer no muta."""

    GLOBALES = [(r, m) for r, m in
                [(r, m) for r, m, a in _rutas(__import__('app').create_app('testing')) if a and a <= GLOBAL_PARAMS]]

    @pytest.mark.parametrize('regla,metodo', GLOBALES, ids=[f'{m} {r}' for r, m in GLOBALES])
    def test_anonimo_denegado(self, app, mundo, regla, metodo):
        r = _llamar(_client(app, None), metodo, regla, mundo.ids)
        assert r.status_code in DENIED, f'{metodo} {regla} -> {r.status_code}'

    @pytest.mark.parametrize('regla,metodo', [(r, m) for r, m in GLOBALES if m != 'GET'],
                             ids=[f'{m} {r}' for r, m in GLOBALES if m != 'GET'])
    def test_viewer_no_muta(self, app, mundo, regla, metodo):
        r = _llamar(_client(app, mundo.viewer), metodo, regla, mundo.ids)
        assert r.status_code in {401, 302, 403}, f'{metodo} {regla} -> {r.status_code}'


class TestRutaHtmlDeIncidente:
    def test_otro_usuario_no_ve_el_incidente(self, app, mundo):
        for user in (mundo.viewer, mundo.otro_analyst, mundo.otro_senior):
            r = _client(app, user).get(f'/incident/{mundo.ids["incident_id"]}')
            assert r.status_code in DENIED, f'{user.role} -> {r.status_code}'

    def test_el_dueno_si(self, app, mundo):
        assert _client(app, mundo.dueno).get(f'/incident/{mundo.ids["incident_id"]}').status_code == 200
