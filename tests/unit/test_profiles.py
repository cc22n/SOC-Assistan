"""
Perfiles de investigación (WP2 de PLAN-FUSION): validación, perfiles del sistema, API, ejecución y CACHÉ.

Cada garantía lleva su control. El caso más delicado es la caché: una ejecución con perfil consulta solo un
subconjunto de APIs, así que NUNCA debe servirse a un análisis normal, ni siquiera después de borrar el perfil
(profile_id pasa a NULL; por eso existe `from_profile`).
"""
from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest

from app import db
from app.models.audit import AuditEvent
from app.models.ioc import IOC, IOCAnalysis, User
from app.models.profile import InvestigationProfile
from app.services.ioc_cache import get_cached_analysis
from app.services.llm_orchestrator import LLMOrchestrator
from app.services.profile_service import (
    MAX_PROFILES_PER_USER, SYSTEM_PROFILES, compatible_apis, ensure_system_profiles, validate_profile_fields,
)
from app.utils.time_utils import utcnow

BASE = '/api/v2/profiles'
OK = dict(name='Mi consulta', description='d', ioc_type='ip', apis=['abuseipdb', 'greynoise'])


def _crear(client, **over):
    return client.post(BASE, json={**OK, **over})


def _perfil_db(owner, name='ajeno', **over):
    """Perfil creado directo en BD: dos clientes autenticados a la vez chocan en el contexto de petición."""
    p = InvestigationProfile(owner_id=owner.id, name=name, ioc_type='ip', apis=['abuseipdb'], **over)
    db.session.add(p)
    db.session.commit()
    return p


# ============================================================================ VALIDACIÓN

class TestValidacion:
    def test_valido(self, app):
        clean, err = validate_profile_fields('  Nombre  ', None, 'ip', ['abuseipdb', 'greynoise'])
        assert err == [] and clean['name'] == 'Nombre' and clean['description'] == '' and clean['llm_synthesis'] is True

    @pytest.mark.parametrize('kw', [
        dict(name=''), dict(name='   '), dict(name=None), dict(name=5), dict(name='x' * 121),
        dict(description='x' * 1001), dict(description=['a']),
        dict(ioc_type='cve'), dict(ioc_type=None),
        dict(apis=[]), dict(apis=None), dict(apis='abuseipdb'), dict(apis=[1, 2]),
        dict(apis=['abuseipdb', 'abuseipdb']),                         # repetidas
        dict(apis=['no_existe']),                                      # inexistente
        dict(apis=['malwarebazaar']),                                  # existe pero es solo para hashes
        dict(apis=['abuseipdb', 'virustotal', 'shodan', 'otx', 'greynoise', 'criminal_ip', 'pulsedive',
                   'threatfox', 'shodan_internetdb', 'censys', 'ipinfo']),   # 11 > MAX_APIS
        dict(llm_synthesis='si'),
    ])
    def test_invalido(self, app, kw):
        base = dict(name='n', description='', ioc_type='ip', apis=['abuseipdb'], llm_synthesis=True)
        clean, err = validate_profile_fields(**{**base, **kw})
        assert clean is None and err

    def test_compatibilidad_se_deriva_del_codigo_no_de_una_lista(self, app):
        assert 'malwarebazaar' in compatible_apis('hash') and 'malwarebazaar' not in compatible_apis('ip')
        assert 'abuseipdb' in compatible_apis('ip') and 'abuseipdb' not in compatible_apis('domain')
        assert set(compatible_apis('ip')) <= set(IOCAnalysis.api_source_names())


class TestPerfilesDelSistema:
    @pytest.mark.parametrize('spec', SYSTEM_PROFILES, ids=[s['name'] for s in SYSTEM_PROFILES])
    def test_todos_son_validos(self, app, spec):
        """Si se quita/renombra una API, un perfil del sistema roto hace fallar esto."""
        clean, err = validate_profile_fields(spec['name'], spec['description'], spec['ioc_type'], spec['apis'])
        assert err == [], err

    def test_control_el_validador_si_detecta_un_perfil_roto(self, app):
        _, err = validate_profile_fields('x', '', 'ip', ['abuseipdb', 'api_borrada'])
        assert err

    def test_hay_ocho_y_cubren_los_cuatro_tipos(self):
        assert len(SYSTEM_PROFILES) == 8
        assert {s['ioc_type'] for s in SYSTEM_PROFILES} == {'ip', 'domain', 'url', 'hash'}
        nombres = [s['name'].lower() for s in SYSTEM_PROFILES]
        assert len(set(nombres)) == len(nombres)

    def test_siembra_idempotente(self, app, db_session):
        assert ensure_system_profiles() == {'created': 8, 'updated': 0}
        assert ensure_system_profiles() == {'created': 0, 'updated': 0}
        assert InvestigationProfile.query.filter_by(is_system=True).count() == 8

    def test_siembra_repara_una_definicion_desviada(self, app, db_session):
        ensure_system_profiles()
        p = InvestigationProfile.query.filter_by(is_system=True, ioc_type='hash').first()
        p.apis = ['virustotal']
        db_session.session.commit()
        assert ensure_system_profiles()['updated'] == 1
        db_session.session.refresh(p)
        assert len(p.apis) > 1


# ============================================================================ API CRUD

class TestCrud:
    def test_crear_y_leer(self, app, db_session, analyst_client, analyst_user):
        r = _crear(analyst_client)
        assert r.status_code == 201
        p = r.get_json()['profile']
        assert p['owner_id'] == analyst_user.id and p['is_system'] is False and p['apis'] == ['abuseipdb', 'greynoise']
        assert analyst_client.get(f"{BASE}/{p['id']}").get_json()['profile']['name'] == 'Mi consulta'
        assert AuditEvent.query.filter_by(action='profile_created', resource_id=p['id']).count() == 1

    def test_el_orden_de_apis_se_conserva(self, app, db_session, analyst_client):
        r = _crear(analyst_client, apis=['greynoise', 'abuseipdb', 'criminal_ip'])
        assert r.get_json()['profile']['apis'] == ['greynoise', 'abuseipdb', 'criminal_ip']

    def test_nombre_duplicado_409_sin_distinguir_mayusculas(self, app, db_session, analyst_client):
        assert _crear(analyst_client).status_code == 201
        assert _crear(analyst_client, name='MI CONSULTA').status_code == 409

    def test_control_otro_usuario_puede_usar_el_mismo_nombre(self, app, db_session, other_client, analyst_user):
        _perfil_db(analyst_user, name='Mi consulta')
        assert _crear(other_client).status_code == 201

    def test_viewer_no_crea(self, app, db_session):
        u = User(username='v1', email='v1@t.local', role='viewer', is_active=True)
        u.password_hash = 'x'
        db_session.session.add(u)
        db_session.session.commit()
        c = app.test_client()
        with c.session_transaction() as s:
            s['_user_id'] = str(u.id)
            s['_fresh'] = True
        assert _crear(c).status_code == 403
        assert InvestigationProfile.query.count() == 0

    def test_anonimo_no_crea_ni_lista(self, client):
        assert _crear(client).status_code in (302, 401)
        assert client.get(BASE).status_code in (302, 401)

    @pytest.mark.parametrize('over', [dict(apis=['no_existe']), dict(ioc_type='cve'), dict(name=''), dict(apis=[])])
    def test_datos_invalidos_400(self, analyst_client, over):
        r = _crear(analyst_client, **over)
        assert r.status_code == 400 and r.get_json()['details']

    def test_cuerpo_no_json(self, analyst_client):
        assert analyst_client.post(BASE, data='texto', content_type='text/plain').status_code == 400

    def test_limite_por_usuario(self, app, db_session, analyst_client, analyst_user):
        for i in range(MAX_PROFILES_PER_USER):
            db_session.session.add(InvestigationProfile(owner_id=analyst_user.id, name=f'p{i}', ioc_type='ip',
                                                        apis=['abuseipdb']))
        db_session.session.commit()
        assert _crear(analyst_client, name='uno mas').status_code == 409

    def test_put_parcial_conserva_lo_no_enviado(self, app, db_session, analyst_client):
        pid = _crear(analyst_client).get_json()['profile']['id']
        r = analyst_client.put(f'{BASE}/{pid}', json={'apis': ['greynoise']})
        p = r.get_json()['profile']
        assert r.status_code == 200 and p['apis'] == ['greynoise'] and p['name'] == 'Mi consulta'
        assert AuditEvent.query.filter_by(action='profile_updated', resource_id=pid).count() == 1

    def test_put_no_cambia_el_tipo(self, app, db_session, analyst_client):
        pid = _crear(analyst_client).get_json()['profile']['id']
        assert analyst_client.put(f'{BASE}/{pid}', json={'ioc_type': 'domain'}).status_code == 400

    def test_put_valida_apis_contra_el_tipo(self, app, db_session, analyst_client):
        pid = _crear(analyst_client).get_json()['profile']['id']
        assert analyst_client.put(f'{BASE}/{pid}', json={'apis': ['malwarebazaar']}).status_code == 400

    def test_borrar(self, app, db_session, analyst_client):
        pid = _crear(analyst_client).get_json()['profile']['id']
        assert analyst_client.delete(f'{BASE}/{pid}').status_code == 200
        assert analyst_client.get(f'{BASE}/{pid}').status_code == 404
        assert AuditEvent.query.filter_by(action='profile_deleted', resource_id=pid).count() == 1


class TestVisibilidadYSistema:
    def test_listado_solo_ve_sistema_y_propios(self, app, db_session, analyst_client, other_user):
        ensure_system_profiles()
        _crear(analyst_client, name='de analyst')
        _perfil_db(other_user, name='de other')
        nombres = {p['name'] for p in analyst_client.get(BASE).get_json()['profiles']}
        assert 'de analyst' in nombres and 'de other' not in nombres
        assert sum(1 for p in analyst_client.get(BASE).get_json()['profiles'] if p['is_system']) == 8

    def test_admin_ve_todos(self, app, db_session, admin_client, analyst_user):
        _perfil_db(analyst_user, name='de analyst')
        assert 'de analyst' in {p['name'] for p in admin_client.get(BASE).get_json()['profiles']}

    def test_filtro_por_tipo(self, app, db_session, analyst_client):
        ensure_system_profiles()
        ps = analyst_client.get(f'{BASE}?ioc_type=hash').get_json()['profiles']
        assert ps and all(p['ioc_type'] == 'hash' for p in ps)
        assert analyst_client.get(f'{BASE}?ioc_type=cve').status_code == 400

    @pytest.mark.parametrize('metodo', ['put', 'delete'])
    def test_sistema_inmutable_incluso_para_admin(self, app, db_session, admin_client, metodo):
        ensure_system_profiles()
        pid = InvestigationProfile.query.filter_by(is_system=True).first().id
        kw = {'json': {'name': 'hackeado'}} if metodo == 'put' else {}
        assert getattr(admin_client, metodo)(f'{BASE}/{pid}', **kw).status_code == 403
        assert db.session.get(InvestigationProfile, pid) is not None
        assert db.session.get(InvestigationProfile, pid).name != 'hackeado'

    def test_sistema_es_legible_por_todos(self, app, db_session, analyst_client):
        ensure_system_profiles()
        pid = InvestigationProfile.query.filter_by(is_system=True).first().id
        assert analyst_client.get(f'{BASE}/{pid}').status_code == 200

    def test_catalogo(self, app, analyst_client):
        cat = analyst_client.get(f'{BASE}/catalog').get_json()
        assert set(cat['catalog']) == {'ip', 'domain', 'url', 'hash'}
        assert cat['catalog']['ip'] == compatible_apis('ip')


# ============================================================================ EJECUCIÓN

HASH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
RES = {'confidence_score': 10, 'risk_level': 'BAJO', 'llm_analysis': {'recommendations': []},
       'mitre_techniques': [], 'processing_time': 0.1, 'timestamp': '2026-11-18T00:00:00+00:00',
       'sources_used': ['abuseipdb'], 'api_results': {'abuseipdb': {'abuse_confidence_score': 0}},
       'api_coverage': {'ok': 1, 'failed': [], 'total': 1, 'incomplete': False}}


def _analizar(client, ioc='203.0.113.5', tipo='ip', **extra):
    with patch('app.routes.api_v2_routes.get_orchestrator') as o:
        o.return_value.analyze_with_intelligence.return_value = RES
        r = client.post('/api/v2/analyze/enhanced', json={'ioc': ioc, 'type': tipo, 'use_llm_planning': True, **extra})
        return r, o.return_value.analyze_with_intelligence


class TestEjecucionPorPerfil:
    def test_usa_las_apis_del_perfil_sin_planificador(self, app, db_session, analyst_client):
        p = _crear(analyst_client, apis=['greynoise', 'abuseipdb'], llm_synthesis=False).get_json()['profile']
        r, mock = _analizar(analyst_client, profile_id=p['id'])
        assert r.status_code == 200
        kw = mock.call_args.kwargs
        assert kw['profile_apis'] == ['greynoise', 'abuseipdb'] and kw['llm_synthesis'] is False
        assert r.get_json()['profile'] == {'id': p['id'], 'name': 'Mi consulta'}

    def test_control_sin_perfil_no_fija_apis(self, app, db_session, analyst_client):
        r, mock = _analizar(analyst_client)
        assert mock.call_args.kwargs['profile_apis'] is None and mock.call_args.kwargs['llm_synthesis'] is True
        assert r.get_json()['profile'] is None

    def test_se_guarda_marcado_como_parcial(self, app, db_session, analyst_client):
        p = _crear(analyst_client).get_json()['profile']
        r, _ = _analizar(analyst_client, profile_id=p['id'])
        a = db.session.get(IOCAnalysis, r.get_json()['analysis_id'])
        assert a.from_profile is True and a.profile_id == p['id']

    def test_perfil_ajeno_404(self, app, db_session, analyst_client, other_user):
        p = {'id': _perfil_db(other_user).id}
        r, mock = _analizar(analyst_client, profile_id=p['id'])
        assert r.status_code == 404 and not mock.called

    def test_perfil_inexistente_404(self, analyst_client):
        assert _analizar(analyst_client, profile_id=999999)[0].status_code == 404

    def test_tipo_distinto_400(self, app, db_session, analyst_client):
        p = _crear(analyst_client).get_json()['profile']           # perfil de IP
        r, mock = _analizar(analyst_client, ioc='example.org', tipo='domain', profile_id=p['id'])
        assert r.status_code == 400 and not mock.called

    def test_perfil_del_sistema_lo_usa_cualquiera(self, app, db_session, other_client):
        ensure_system_profiles()
        p = InvestigationProfile.query.filter_by(is_system=True, ioc_type='ip').first()
        r, mock = _analizar(other_client, profile_id=p.id)
        assert r.status_code == 200 and mock.call_args.kwargs['profile_apis'] == p.apis

    def test_perfil_borrado_antes_de_ejecutar_404(self, app, db_session, analyst_client):
        pid = _crear(analyst_client).get_json()['profile']['id']
        analyst_client.delete(f'{BASE}/{pid}')
        assert _analizar(analyst_client, profile_id=pid)[0].status_code == 404


class TestOrquestador:
    @pytest.fixture
    def orch(self, app, app_ctx):
        o = LLMOrchestrator()
        o._clients_initialized = True
        o.api_clients = {n: object() for n in ('abuseipdb', 'greynoise', 'shodan')}
        return o

    def test_consulta_exactamente_las_del_perfil_en_orden_y_sin_llm(self, orch):
        with patch.object(orch, '_execute_apis', return_value={'greynoise': {'noise': False}, 'abuseipdb': {'x': 1}}) as ex, \
                patch.object(orch, '_plan_analysis_with_llm') as plan, \
                patch.object(orch, '_synthesize_with_llm') as synth:
            r = orch.analyze_with_intelligence('1.2.3.4', 'ip', profile_apis=['greynoise', 'abuseipdb'],
                                               llm_synthesis=False)
        assert ex.call_args.args[2] == ['greynoise', 'abuseipdb']
        assert not plan.called and not synth.called
        assert 'sin síntesis LLM' in r['llm_analysis']['executive_summary']
        assert r['llm_analysis']['threat_level'] == r['risk_level']

    def test_omite_apis_sin_cliente(self, orch):
        with patch.object(orch, '_execute_apis', return_value={}) as ex, patch.object(orch, '_synthesize_with_llm'):
            orch.analyze_with_intelligence('1.2.3.4', 'ip', profile_apis=['abuseipdb', 'virustotal'])
        assert ex.call_args.args[2] == ['abuseipdb']

    def test_control_con_sintesis_si_llama_al_llm(self, orch):
        with patch.object(orch, '_execute_apis', return_value={'abuseipdb': {'x': 1}}), \
                patch.object(orch, '_synthesize_with_llm', return_value={'recommendations': []}) as synth:
            orch.analyze_with_intelligence('1.2.3.4', 'ip', profile_apis=['abuseipdb'], llm_synthesis=True)
        assert synth.called

    def test_control_sin_perfil_usa_el_planificador(self, orch):
        with patch.object(orch, '_execute_apis', return_value={}), \
                patch.object(orch, '_plan_analysis_with_llm', return_value=['abuseipdb']) as plan, \
                patch.object(orch, '_synthesize_with_llm', return_value={}):
            orch.analyze_with_intelligence('1.2.3.4', 'ip', use_llm_planning=True)
        assert plan.called


@pytest.fixture
def app_ctx(app):
    with app.app_context():
        yield


# ============================================================================ CACHÉ

def _analisis(ioc, *, from_profile=False, profile_id=None, minutos=1, riesgo='BAJO'):
    a = IOCAnalysis(ioc_id=ioc.id, confidence_score=10, risk_level=riesgo, sources_used=['abuseipdb'],
                    from_profile=from_profile, profile_id=profile_id, created_at=utcnow() - timedelta(minutes=minutos))
    db.session.add(a)
    db.session.commit()
    return a


@pytest.fixture
def ioc(app, db_session):
    i = IOC(value='198.51.100.7', ioc_type='ip')
    db_session.session.add(i)
    db_session.session.commit()
    return i


class TestCache:
    def test_control_analisis_normal_se_sirve_normal(self, ioc):
        a = _analisis(ioc)
        assert get_cached_analysis(ioc.value, 'ip')['analysis_id'] == a.id

    def test_una_ejecucion_de_perfil_no_se_sirve_a_un_analisis_normal(self, ioc, analyst_user):
        p = InvestigationProfile(owner_id=analyst_user.id, name='p', ioc_type='ip', apis=['abuseipdb'])
        db.session.add(p)
        db.session.commit()
        _analisis(ioc, from_profile=True, profile_id=p.id)
        assert get_cached_analysis(ioc.value, 'ip') is None

    def test_el_normal_mas_reciente_gana_pero_el_de_perfil_no_lo_tapa(self, ioc, analyst_user):
        """Sin el filtro, el análisis de perfil (más reciente) taparía al completo."""
        p = InvestigationProfile(owner_id=analyst_user.id, name='p', ioc_type='ip', apis=['abuseipdb'])
        db.session.add(p)
        db.session.commit()
        completo = _analisis(ioc, minutos=30)
        _analisis(ioc, from_profile=True, profile_id=p.id, minutos=1)
        assert get_cached_analysis(ioc.value, 'ip')['analysis_id'] == completo.id

    def test_el_perfil_solo_recibe_su_propia_cache(self, ioc, analyst_user):
        p1 = InvestigationProfile(owner_id=analyst_user.id, name='p1', ioc_type='ip', apis=['abuseipdb'])
        p2 = InvestigationProfile(owner_id=analyst_user.id, name='p2', ioc_type='ip', apis=['greynoise'])
        db.session.add_all([p1, p2])
        db.session.commit()
        a1 = _analisis(ioc, from_profile=True, profile_id=p1.id)
        assert get_cached_analysis(ioc.value, 'ip', profile_id=p1.id)['analysis_id'] == a1.id
        assert get_cached_analysis(ioc.value, 'ip', profile_id=p2.id) is None

    def test_un_analisis_normal_no_se_sirve_a_un_perfil(self, ioc, analyst_user):
        p = InvestigationProfile(owner_id=analyst_user.id, name='p', ioc_type='ip', apis=['abuseipdb'])
        db.session.add(p)
        db.session.commit()
        _analisis(ioc)
        assert get_cached_analysis(ioc.value, 'ip', profile_id=p.id) is None

    def test_borrar_el_perfil_no_convierte_su_analisis_en_completo(self, ioc, analyst_client, analyst_user):
        """EL fallo de diseño evitado: ON DELETE SET NULL dejaba profile_id=NULL y la caché lo servía como completo."""
        pid = _crear(analyst_client).get_json()['profile']['id']
        a = _analisis(ioc, from_profile=True, profile_id=pid)
        assert analyst_client.delete(f'{BASE}/{pid}').status_code == 200
        db.session.refresh(a)
        assert a.profile_id is None and a.from_profile is True        # el análisis sobrevive, marcado parcial
        assert get_cached_analysis(ioc.value, 'ip') is None

    def test_control_sin_from_profile_el_borrado_si_habria_filtrado(self, ioc, analyst_client):
        """Demuestra que el test anterior detecta el defecto: con solo profile_id NULL el parcial se serviría."""
        pid = _crear(analyst_client).get_json()['profile']['id']
        a = _analisis(ioc, from_profile=False, profile_id=pid)        # simula el diseño ingenuo
        analyst_client.delete(f'{BASE}/{pid}')
        assert get_cached_analysis(ioc.value, 'ip')['analysis_id'] == a.id


# ============================================================================ INTERFAZ

class TestInterfaz:
    def test_pagina_de_perfiles_cumple_la_csp(self, analyst_client):
        r = analyst_client.get('/profiles')
        html = r.get_data(as_text=True)
        assert r.status_code == 200 and 'Perfiles de investigación' in html
        assert 'onclick=' not in html and 'onchange=' not in html and '<script nonce=' in html

    def test_anonimo_no_ve_la_pagina(self, client):
        assert client.get('/profiles').status_code in (302, 401)

    def test_enlace_en_la_barra_lateral(self, analyst_client):
        assert '/profiles' in analyst_client.get('/dashboard').get_data(as_text=True)

    def test_la_pagina_de_analisis_tiene_el_selector_y_envia_profile_id(self, analyst_client):
        html = analyst_client.get('/analyze').get_data(as_text=True)
        assert 'id="profileSelector"' in html
        assert 'body.profile_id = Number(profileId)' in html

    def test_las_llamadas_fetch_de_la_pagina_de_perfiles_existen(self, app):
        """Cada ruta a la que llama profiles.html debe existir con su método."""
        reglas = {(r.rule.replace('<int:profile_id>', '{id}'), m) for r in app.url_map.iter_rules() for m in r.methods}
        for ruta, metodo in [('/api/v2/profiles', 'GET'), ('/api/v2/profiles', 'POST'),
                             ('/api/v2/profiles/catalog', 'GET'), ('/api/v2/profiles/{id}', 'PUT'),
                             ('/api/v2/profiles/{id}', 'DELETE')]:
            assert (ruta, metodo) in reglas, (ruta, metodo)
