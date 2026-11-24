"""
Política de salida (WP4 de PLAN-FUSION): un IOC interno o mal formado NO sale hacia APIs de terceros, por NINGUNA entrada.

Antecedente (verificado por ejecución el 2026-11-20): la regla "una IP privada no llega a ninguna API externa" solo se aplicaba en
`validate_ioc` (análisis profundo). La ruta principal y el chat dejaban salir IPs privadas, URLs a 169.254.169.254, localhost y
dominios .lan/.local a hasta 10 terceros; en el chat el IOC lo decide el MODELO sin validación. Cada garantía lleva su control.
"""
import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from app import db
from app.models.audit import AuditEvent
from app.models.ioc import IOC
from app.services import async_executor
from app.services.llm_orchestrator import LLMOrchestrator
from app.utils import egress_policy
from app.utils.egress_policy import (
    Decision, EgressDenied, audit_denied, enforce, evaluate, explain, host_internal_rule, mask_text,
)
from app.utils.security import sanitize_chat_message, sanitize_user_context

ROOT = Path(__file__).resolve().parents[2]
SHA = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

# (tipo, valor, regla esperada) — IOCs que NUNCA deben salir
INTERNOS = [
    ('ip', '10.0.0.5', 'ip_interna'), ('ip', '172.16.9.9', 'ip_interna'), ('ip', '192.168.1.10', 'ip_interna'),
    ('ip', '127.0.0.1', 'ip_interna'), ('ip', '169.254.169.254', 'ip_interna'), ('ip', '100.64.1.1', 'ip_interna'),
    ('ip', '::1', 'ip_interna'), ('ip', 'fe80::1', 'ip_interna'), ('ip', 'fd00::5', 'ip_interna'),
    ('url', 'http://192.168.1.10/admin/login', 'ip_interna'), ('url', 'http://10.20.30.40:8080/x', 'ip_interna'),
    ('url', 'http://169.254.169.254/latest/meta-data/', 'ip_interna'), ('url', 'http://127.1/', 'ip_interna'),
    ('url', 'http://0x7f.0.0.1/', 'ip_interna'), ('url', 'http://2130706433/x', 'ip_interna'),
    ('url', 'http://017700000001/', 'ip_interna'), ('url', 'http://evil.com@10.0.0.1/', 'ip_interna'),
    ('url', 'http://10.0.0.1#@evil.com/', 'ip_interna'),
    ('url', 'http://localhost:5000/debug', 'host_interno'), ('url', 'https://intranet.corp.local/portal', 'host_interno'),
    ('url', 'http://printer/', 'host_interno'), ('url', 'http://server01.internal/a', 'host_interno'),
    ('domain', 'intranet.corp.local', 'host_interno'), ('domain', 'server01.internal', 'host_interno'),
    ('domain', 'dc01.empresa.lan', 'host_interno'), ('domain', 'host.home.arpa', 'host_interno'),
    ('domain', 'fileserver.corp', 'host_interno'), ('domain', 'wiki.intranet', 'host_interno'),
]
# (tipo, valor) — IOCs públicos que SÍ deben pasar (controles: sin ellos "todo denegado" también cumpliría)
PUBLICOS = [
    ('ip', '8.8.8.8'), ('ip', '1.1.1.1'), ('ip', '192.0.2.10'), ('ip', '203.0.113.7'), ('ip', '2001:4860:4860::8888'),
    ('url', 'https://example.org/path?q=1'), ('url', 'http://203.0.113.9/a.sh'), ('url', 'https://www.google.com/'),
    ('domain', 'google.com'), ('domain', 'corp.example.com'), ('domain', 'a.local.com'), ('domain', 'mylocal.com'),
    ('domain', 'notcorp.io'), ('domain', 'lan.example.org'),
    ('hash', SHA), ('hash', 'd41d8cd98f00b204e9800998ecf8427e'), ('cve', 'CVE-2021-44228'),
]
FORMATO_MALO = [('domain', 'cualquier cosa; DROP TABLE'), ('domain', 'x'), ('domain', ''), ('url', 'ftp://example.org/a'),
                ('url', 'javascript:alert(1)'), ('ip', '999.1.1.1'), ('ip', 'no-es-ip'), ('hash', 'abc'), ('cve', 'CVE-1-1'),
                ('url', '[IP_INTERNA]'), ('domain', '[HOST_INTERNO]')]


@pytest.fixture
def app_ctx(app):
    with app.app_context():
        yield


# ============================================================================ FUNCIÓN PURA

class TestEvaluar:
    @pytest.mark.parametrize('tipo,valor,regla', INTERNOS)
    def test_internos_se_deniegan_con_su_regla(self, tipo, valor, regla):
        v = evaluate(valor, tipo)
        assert v.decision == Decision.DENY and v.rule == regla and v.reason

    @pytest.mark.parametrize('tipo,valor', PUBLICOS)
    def test_control_publicos_se_permiten(self, tipo, valor):
        v = evaluate(valor, tipo)
        assert v.decision == Decision.ALLOW and v.allowed and v.rule == ''

    @pytest.mark.parametrize('tipo,valor', FORMATO_MALO)
    def test_formato_invalido_se_deniega(self, tipo, valor):
        """En el chat el IOC lo decide el modelo: no se confía en que sea un IOC."""
        v = evaluate(valor, tipo)
        assert v.decision == Decision.DENY and v.rule in ('formato_invalido', 'ip_interna', 'host_interno')

    @pytest.mark.parametrize('valor', [None, '', '   '])
    def test_vacio_se_deniega(self, valor):
        assert evaluate(valor, 'domain').decision == Decision.DENY

    @pytest.mark.parametrize('tipo', [None, 'unknown', 'mac', ''])
    def test_tipo_desconocido_no_se_bloquea_porque_no_consulta_ninguna_api(self, tipo):
        assert evaluate('lo que sea', tipo).allowed

    def test_los_rangos_de_documentacion_siguen_permitidos(self):
        """Son válidos como IOC de ejemplo: 192.0.2/24, 198.51.100/24, 203.0.113/24."""
        for ip in ('192.0.2.1', '198.51.100.1', '203.0.113.1'):
            assert evaluate(ip, 'ip').allowed

    def test_nunca_emite_require_approval_ni_mask_para_iocs(self):
        """REQUIRE_APPROVAL está reservado y MASK es solo para texto libre."""
        for tipo, valor, _ in INTERNOS:
            assert evaluate(valor, tipo).decision == Decision.DENY
        for tipo, valor in PUBLICOS + FORMATO_MALO:
            assert evaluate(valor, tipo).decision in (Decision.ALLOW, Decision.DENY)

    def test_sin_estado_misma_entrada_mismo_veredicto(self):
        assert evaluate('10.0.0.5', 'ip') == evaluate('10.0.0.5', 'ip')

    def test_el_sufijo_se_compara_por_limite_de_etiqueta_nunca_por_subcadena(self):
        assert host_internal_rule('notlocal.com') is None and host_internal_rule('mylan.com') is None
        assert host_internal_rule('a.local') is not None and host_internal_rule('local') is not None

    @pytest.mark.parametrize('host', ['server.mylan', 'x.newlocal', 'host.myhome', 'a.bigcorp', 'b.notinternal', 'c.xprivate', 'd.biglocalhost'])
    def test_un_host_que_TERMINA_en_las_letras_del_sufijo_pero_no_es_ese_sufijo_es_publico(self, host):
        """Caza la comparación por subcadena: 'server.mylan' termina en 'lan' pero su TLD es 'mylan', no 'lan'."""
        assert host_internal_rule(host) is None
        assert evaluate(host, 'domain').allowed

    @pytest.mark.parametrize('host', ['server.lan', 'x.local', 'host.home', 'a.corp', 'b.internal', 'c.private', 'd.home.arpa'])
    def test_control_el_mismo_sufijo_completo_si_es_interno(self, host):
        assert host_internal_rule(host) is not None

    def test_punto_final_y_mayusculas(self):
        assert host_internal_rule('DC01.EMPRESA.LAN.') is not None

    def test_zona_ipv6(self):
        assert host_internal_rule('fe80::1%eth0') is not None

    def test_host_vacio_falla_cerrado(self):
        assert host_internal_rule('')[0] == 'host_invalido' and host_internal_rule(None)[0] == 'host_invalido'

    def test_explain_distingue_formato_de_interno(self):
        assert 'rechazado' in explain(evaluate('x;', 'domain')) and 'interno' in explain(evaluate('10.0.0.5', 'ip')).lower()


class TestDominiosPropios:
    def test_declarados_en_configuracion(self, app, app_ctx):
        app.config['EGRESS_INTERNAL_DOMAINS'] = ('empresa.com',)
        try:
            assert evaluate('intranet.empresa.com', 'domain').rule == 'dominio_propio'
            assert evaluate('empresa.com', 'domain').rule == 'dominio_propio'
            assert evaluate('https://wiki.empresa.com/x', 'url').rule == 'dominio_propio'
            assert evaluate('noempresa.com', 'domain').allowed           # límite de etiqueta
            assert evaluate('empresa.com.evil.org', 'domain').allowed    # el dominio propio no es el sufijo
            assert evaluate('google.com', 'domain').allowed
        finally:
            app.config['EGRESS_INTERNAL_DOMAINS'] = ()

    def test_control_sin_declarar_no_se_detecta(self, app, app_ctx):
        """El límite documentado: un dominio interno con nombre público no se detecta solo."""
        assert evaluate('intranet.empresa.com', 'domain').allowed

    def test_parametro_explicito(self):
        assert evaluate('a.acme.test', 'domain', extra_domains=('acme.test',)).rule == 'dominio_propio'

    def test_la_variable_de_entorno_se_parsea(self, monkeypatch):
        monkeypatch.setenv('EGRESS_INTERNAL_DOMAINS', ' Empresa.COM , .corp.empresa.com,, ')
        import importlib
        from app import config
        importlib.reload(config)
        try:
            assert config.Config.EGRESS_INTERNAL_DOMAINS == ('empresa.com', 'corp.empresa.com')
        finally:
            monkeypatch.delenv('EGRESS_INTERNAL_DOMAINS')
            importlib.reload(config)
        assert config.Config.EGRESS_INTERNAL_DOMAINS == ()


class TestEnforce:
    def test_lanza_con_el_veredicto(self):
        with pytest.raises(EgressDenied) as e:
            enforce('10.0.0.5', 'ip')
        assert e.value.verdict.rule == 'ip_interna' and isinstance(e.value, ValueError)

    def test_control_publico_no_lanza(self):
        assert enforce('8.8.8.8', 'ip').allowed


class TestMascara:
    @pytest.mark.parametrize('texto,esperado,n', [
        ('host 10.1.2.3 y 8.8.8.8 caidos', 'host [IP_INTERNA] y 8.8.8.8 caidos', 1),
        ('mira http://dc01.empresa.local/a.php', 'mira http://[HOST_INTERNO]/a.php', 1),
        ('curl http://169.254.169.254/latest y localhost', 'curl http://[IP_INTERNA]/latest y [HOST_INTERNO]', 2),
        ('server01.internal y 192.168.0.1 y 10.0.0.1', '[HOST_INTERNO] y [IP_INTERNA] y [IP_INTERNA]', 3),
        ('cae host.local. y dc01.corp, revisa', 'cae [HOST_INTERNO]. y [HOST_INTERNO], revisa', 2),       # punto/coma finales
    ])
    def test_enmascara_lo_interno(self, texto, esperado, n):
        assert mask_text(texto) == (esperado, n)

    @pytest.mark.parametrize('texto', [
        'version 1.2.3.4 en example.com', f'hash {SHA}', 'CVE-2024-3094 afecta a xz', 'IP publica 8.8.8.8 y 1.1.1.1',
        'dominio google.com y a.local.com', 'texto normal sin nada', '', 'mylocal.com y notcorp.io',
    ])
    def test_control_no_toca_lo_publico(self, texto):
        assert mask_text(texto) == (texto, 0)

    def test_none(self):
        assert mask_text(None) == ('', 0)

    def test_dominios_propios_en_texto(self, app, app_ctx):
        app.config['EGRESS_INTERNAL_DOMAINS'] = ('empresa.com',)
        try:
            assert mask_text('revisa wiki.empresa.com ahora') == ('revisa [HOST_INTERNO] ahora', 1)
        finally:
            app.config['EGRESS_INTERNAL_DOMAINS'] = ()

    def test_el_contexto_del_analista_se_enmascara_antes_del_llm(self):
        assert '10.9.8.7' not in sanitize_user_context('el host 10.9.8.7 beaconea a 8.8.8.8')
        assert '8.8.8.8' in sanitize_user_context('el host 10.9.8.7 beaconea a 8.8.8.8')

    def test_el_chat_se_enmascara_antes_del_llm(self):
        out = sanitize_chat_message('analiza http://dc01.empresa.lan/x desde 192.168.0.4')
        assert 'empresa.lan' not in out and '192.168.0.4' not in out and '[HOST_INTERNO]' in out and '[IP_INTERNA]' in out

    def test_el_enmascarado_se_aplica_aunque_el_texto_se_trunque(self):
        out = sanitize_user_context('10.0.0.1 ' * 200)
        assert '10.0.0.1' not in out


# ============================================================================ MATRIZ DE ENTRADAS

RES = {'confidence_score': 0, 'risk_level': 'LIMPIO', 'llm_analysis': {}, 'mitre_techniques': [], 'processing_time': 0.1,
       'timestamp': '2026-11-20T00:00:00+00:00', 'sources_used': ['abuseipdb'], 'api_results': {'abuseipdb': {'x': 1}},
       'api_coverage': {'ok': 1, 'failed': [], 'total': 1, 'incomplete': False}}


def _post_analyze(client, valor, tipo):
    body = {'ioc': valor, 'use_llm_planning': False}
    if tipo:
        body['type'] = tipo
    with patch('app.routes.api_v2_routes.get_orchestrator') as o, patch('app.services.ioc_cache.get_cached_analysis', return_value=None), \
            patch('app.utils.http_client.get_http_session') as net:
        o.return_value.analyze_with_intelligence.return_value = RES
        r = client.post('/api/v2/analyze/enhanced', json=body)
        return r, o.return_value.analyze_with_intelligence, net


class TestRutaPrincipal:
    @pytest.mark.parametrize('tipo,valor,regla', INTERNOS)
    @pytest.mark.parametrize('tipado', [True, False])
    def test_interno_422_sin_llegar_al_orquestador_ni_a_la_red(self, app, db_session, analyst_client, tipo, valor, regla, tipado):
        r, analiza, net = _post_analyze(analyst_client, valor, tipo if tipado else None)
        assert r.status_code in (400, 422), (valor, r.status_code)          # sin tipo, el detector puede no reconocerlo: 400
        if r.status_code == 422 and r.get_json().get('egress_denied'):
            assert r.get_json()['rule'] == regla and 'interno' in r.get_json()['error'].lower()
        assert not analiza.called and not net.called
        assert IOC.query.filter_by(value=valor).count() == 0                # ni siquiera se crea el IOC

    # (la ruta principal solo acepta IPv4 por su esquema: limitación previa de la plataforma, ajena a esta política)
    @pytest.mark.parametrize('tipo,valor', [p for p in PUBLICOS if ':' not in p[1]])
    def test_control_publicos_llegan_al_orquestador(self, app, db_session, analyst_client, tipo, valor):
        r, analiza, _ = _post_analyze(analyst_client, valor, tipo)
        assert r.status_code == 200 and analiza.called, (valor, r.status_code, r.get_data(as_text=True)[:150])

    def test_queda_auditado_con_regla_y_origen(self, app, db_session, analyst_client, analyst_user):
        _post_analyze(analyst_client, '169.254.169.254', 'ip')
        ev = AuditEvent.query.filter_by(action='egress_denied').one()
        assert ev.success is False and ev.user_id == analyst_user.id
        assert ev.details['rule'] == 'ip_interna' and ev.details['origin'] == 'analyze' and ev.details['ioc'] == '169.254.169.254'

    def test_un_permitido_no_se_audita(self, app, db_session, analyst_client):
        _post_analyze(analyst_client, '8.8.8.8', 'ip')
        assert AuditEvent.query.filter_by(action='egress_denied').count() == 0

    def test_el_rechazo_va_antes_de_la_cache_y_de_la_lista_blanca(self, app, db_session, analyst_client):
        db_session.session.add(IOC(value='10.0.0.5', ioc_type='ip', is_whitelisted=True, whitelist_reason='x'))
        db_session.session.commit()
        r, _, _ = _post_analyze(analyst_client, '10.0.0.5', 'ip')
        assert r.status_code == 422 and not r.get_json().get('whitelisted')

    def test_el_audit_sobrevive_al_rechazo(self, app, db_session, analyst_client):
        _post_analyze(analyst_client, 'http://192.168.1.10/a', 'url')
        db_session.session.expire_all()
        assert AuditEvent.query.filter_by(action='egress_denied').count() == 1


class TestRutaProfunda:
    @pytest.mark.parametrize('tipo,valor,regla', [i for i in INTERNOS if i[0] in ('url', 'domain')][:8] + [('ip', '172.16.0.9', 'ip_interna')])
    def test_interno_rechazado_sin_llamar_al_servicio(self, app, db_session, admin_client, tipo, valor, regla):
        with patch('app.routes.deep_analysis_routes.DeepAnalysisService') as svc:
            r = admin_client.post('/api/v2/deep/analyze', json={'ioc': valor, 'type': tipo})
        assert r.status_code in (400, 422) and not svc.called
        if r.status_code == 422:
            assert r.get_json()['rule'] == regla
            assert AuditEvent.query.filter_by(action='egress_denied').count() == 1


class TestOrquestador:
    @pytest.fixture
    def orq(self, app_ctx):
        o = LLMOrchestrator()
        o._clients_initialized = True
        o.api_clients = {n: object() for n in ('greynoise', 'abuseipdb', 'virustotal', 'urlhaus', 'otx', 'threatfox')}
        return o

    @pytest.mark.parametrize('tipo,valor,regla', INTERNOS)
    def test_analyze_with_intelligence_no_consulta_ninguna_api(self, orq, tipo, valor, regla):
        """El punto de entrada del chat: antes una IP privada iba a 7 APIs, una URL interna a 5, un dominio interno a 8."""
        with patch.object(orq, '_execute_apis') as ex, patch.object(orq, '_synthesize_with_llm'):
            with pytest.raises(EgressDenied) as e:
                orq.analyze_with_intelligence(valor, tipo, use_llm_planning=False)
        assert not ex.called and e.value.verdict.rule == regla

    @pytest.mark.parametrize('tipo,valor', PUBLICOS)
    def test_control_publicos_si_consultan(self, orq, tipo, valor):
        with patch.object(orq, '_execute_apis', return_value={'abuseipdb': {'x': 1}}) as ex, \
                patch.object(orq, '_synthesize_with_llm', return_value={}):
            orq.analyze_with_intelligence(valor, tipo, use_llm_planning=False)
        assert ex.called

    @pytest.mark.parametrize('tipo,valor', FORMATO_MALO[:6])
    def test_una_cadena_arbitraria_decidida_por_el_modelo_no_sale(self, orq, tipo, valor):
        with patch.object(orq, '_execute_apis') as ex:
            with pytest.raises(EgressDenied):
                orq.analyze_with_intelligence(valor, tipo, use_llm_planning=False)
        assert not ex.called

    def test_con_perfil_tambien(self, orq):
        with patch.object(orq, '_execute_apis') as ex:
            with pytest.raises(EgressDenied):
                orq.analyze_with_intelligence('10.0.0.5', 'ip', profile_apis=['abuseipdb'], llm_synthesis=False)
        assert not ex.called

    def test_el_contexto_del_analista_llega_enmascarado_al_llm(self, orq):
        vistos = {}
        with patch.object(orq, '_execute_apis', return_value={'abuseipdb': {'x': 1}}), \
                patch.object(orq, '_synthesize_with_llm', side_effect=lambda ioc, t, r, ctx, d='basic': vistos.setdefault('ctx', ctx) or {}):
            orq.analyze_with_intelligence('8.8.8.8', 'ip', user_context='lo vimos desde 10.9.8.7 y dc01.empresa.lan', use_llm_planning=False)
        assert '10.9.8.7' not in vistos['ctx'] and 'empresa.lan' not in vistos['ctx'] and '[IP_INTERNA]' in vistos['ctx']


class TestDespacho:
    """E2, defensa en profundidad: aunque alguien llame al despacho directamente, no sale nada."""

    @pytest.mark.parametrize('tipo,valor,regla', INTERNOS)
    def test_execute_apis_parallel_falla_cerrado(self, tipo, valor, regla):
        cliente = MagicMock()
        with pytest.raises(EgressDenied):
            async_executor.execute_apis_parallel(valor, tipo, ['abuseipdb', 'virustotal'], {'abuseipdb': cliente, 'virustotal': cliente})
        assert not cliente.method_calls and not cliente.called

    def test_control_un_ioc_publico_si_ejecuta_la_api(self):
        cliente = SimpleNamespace(check_ip=lambda ip: {'abuse_confidence_score': 0})
        r = async_executor.execute_apis_parallel('8.8.8.8', 'ip', ['abuseipdb'], {'abuseipdb': cliente})
        assert r['abuseipdb'] == {'abuse_confidence_score': 0}


class TestChat:
    @pytest.fixture
    def orq(self, app_ctx):
        o = LLMOrchestrator()
        o._clients_initialized = True
        return o

    @pytest.mark.parametrize('tipo,valor,regla', INTERNOS)
    def test_el_ioc_que_decide_el_modelo_se_valida_igual_que_uno_tecleado(self, orq, db_session, tipo, valor, regla):
        llm = SimpleNamespace(provider='x')
        intent = {'ioc_value': valor, 'ioc_type': tipo}
        with patch.object(orq, 'analyze_with_intelligence') as ana:
            r = orq._handle_new_ioc_analysis(llm, intent, 'analiza esto', None, '', None, None)
        assert not ana.called
        assert r['egress_denied'] is True and r['rule'] == regla and r['requires_analysis'] is False
        assert 'interno' in r['response'].lower()
        ev = AuditEvent.query.filter_by(action='egress_denied').one()
        assert ev.details['origin'] == 'chat' and ev.details['ioc'] == valor

    def test_control_un_ioc_publico_se_analiza(self, orq, db_session):
        llm = SimpleNamespace(provider='x')
        with patch.object(orq, 'analyze_with_intelligence', side_effect=RuntimeError('llegó al análisis')) as ana, \
                patch.object(orq, '_get_ioc_history', return_value=[]):
            with pytest.raises(RuntimeError, match='llegó al análisis'):
                orq._handle_new_ioc_analysis(llm, {'ioc_value': '8.8.8.8', 'ioc_type': 'ip'}, 'm', None, '', None, None)
        assert ana.called

    def test_un_ioc_con_formato_roto_no_se_analiza(self, orq, db_session):
        llm = SimpleNamespace(provider='x')
        with patch.object(orq, 'analyze_with_intelligence') as ana:
            r = orq._handle_new_ioc_analysis(llm, {'ioc_value': 'x; DROP TABLE', 'ioc_type': 'domain'}, 'm', None, '', None, None)
        assert not ana.called and r['rule'] == 'formato_invalido' and 'rechazado' in r['response']

    def test_el_analisis_profundo_por_chat_tambien(self, orq, db_session):
        """IP en decimal: no la enmascara la regex de texto, pero sí la reconoce la política (2130706433 = 127.0.0.1)."""
        llm = SimpleNamespace(provider='x', provider_name='x')
        with patch.object(orq, '_get_available_llm', return_value=llm), patch.object(orq, '_user_can_deep_analyze', return_value=True), \
                patch.object(orq, '_handle_deep_analysis_request') as deep, patch.object(orq, '_initialize_clients'):
            r = orq.chat_analysis('haz un análisis profundo de http://2130706433/x', user_id=None)
        assert not deep.called and r.get('egress_denied') is True and r['rule'] == 'ip_interna'

    def test_una_ip_privada_tecleada_en_el_chat_llega_enmascarada_y_no_se_extrae(self, orq, db_session):
        """El mensaje se enmascara ANTES de extraer IOCs: el extractor ya no la ve."""
        llm = SimpleNamespace(provider='x', provider_name='x')
        with patch.object(orq, '_get_available_llm', return_value=llm), patch.object(orq, '_user_can_deep_analyze', return_value=True), \
                patch.object(orq, '_handle_deep_analysis_request') as deep, patch.object(orq, '_initialize_clients'), \
                patch.object(orq, '_call_llm', return_value={}) as call:
            orq.chat_analysis('haz un análisis profundo de 10.1.2.3', user_id=None)
        assert not deep.called
        for c in call.call_args_list:
            assert '10.1.2.3' not in str(c)


class TestAuditoria:
    def test_audit_denied_no_lanza_si_falla(self, app, db_session):
        with patch('app.models.audit.AuditEvent.log', side_effect=RuntimeError('db caída')):
            audit_denied(evaluate('10.0.0.5', 'ip'), '10.0.0.5', 'ip', 'analyze', None)        # no debe propagar

    def test_trunca_el_ioc(self, app, db_session):
        audit_denied(evaluate('http://10.0.0.1/' + 'a' * 500, 'url'), 'http://10.0.0.1/' + 'a' * 500, 'url', 'analyze', None)
        assert len(AuditEvent.query.filter_by(action='egress_denied').one().details['ioc']) == 200


# ============================================================================ GUARDAS ESTÁTICAS

class TestGuardasEstaticas:
    def test_toda_la_salida_http_pasa_por_http_client(self):
        """TODA llamada HTTP pasa por app/utils/http_client.py (la única excepción, la descarga del catálogo MITRE, ya también). Una
        llamada directa a `requests` esquivaría el punto único donde se vigila la salida y donde las excepciones se redactan de
        secretos (prelaunch-report-4 A2)."""
        directas = []
        for f in (ROOT / 'app').rglob('*.py'):
            for n, linea in enumerate(f.read_text(encoding='utf-8').splitlines(), 1):
                if re.search(r'\brequests\.(get|post|put|patch|delete|request)\(', linea) and not linea.strip().startswith('#'):
                    directas.append(f'{f.relative_to(ROOT)}:{n}')
        assert directas == [], directas

    def test_los_dos_puntos_de_entrada_llaman_a_enforce(self):
        for archivo, funcion in (('app/services/llm_orchestrator.py', 'def analyze_with_intelligence'),
                                 ('app/services/async_executor.py', 'def execute_apis_parallel')):
            src = (ROOT / archivo).read_text(encoding='utf-8')
            cuerpo = src[src.index(funcion):]
            assert 'enforce(' in cuerpo[:cuerpo.index('\n    def ') if '\n    def ' in cuerpo[10:] else 4000][:6000], (archivo, funcion)

    def test_require_approval_esta_reservado_y_no_se_usa_fuera_del_modulo(self):
        usos = [str(f.relative_to(ROOT)) for f in (ROOT / 'app').rglob('*.py')
                if 'REQUIRE_APPROVAL' in f.read_text(encoding='utf-8') and f.name != 'egress_policy.py']
        assert usos == []

    def test_la_politica_no_depende_de_flask_para_los_ioc(self):
        """Función pura: evaluate no necesita contexto de aplicación (solo lo usa para leer EGRESS_INTERNAL_DOMAINS)."""
        assert evaluate('10.0.0.5', 'ip').decision == Decision.DENY
