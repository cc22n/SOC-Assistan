"""
Feeds proactivos de CVEs (WP6 de PLAN-FUSION): casado contra el stack, fuentes, ejecutor, API, UI y despliegue.

Las respuestas de tests/fixtures/feeds/ son REALES (capturadas el 2026-11-19). Cada garantía lleva su control.
"""
import json
import threading
from datetime import date, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import text

from app import db
from app.models.audit import AuditEvent
from app.models.feed import FeedItem, FeedRun, TechStackEntry
from app.models.ioc import User
from app.services import cve_clients, feed_runner, feed_sources
from app.services.feed_matching import entry_is_valid, entry_matches, match_entries, tokens
from app.services.feed_sources import FeedError, fetch_epss, fetch_kev, fetch_nvd_recent

ROOT = Path(__file__).resolve().parents[2]
FX = ROOT / 'tests' / 'fixtures' / 'feeds'
NOW = datetime(2026, 11, 19, 12, 0, 0)


def _j(name):
    return json.loads((FX / name).read_text(encoding='utf-8'))


def _resp(status=200, payload=None, json_error=False):
    m = MagicMock()
    m.status_code = status
    if json_error:
        m.json.side_effect = ValueError('no json')
    else:
        m.json.return_value = payload
    return m


@pytest.fixture
def app_ctx(app):
    with app.app_context():
        yield


def _entry(vendor=None, product=None, id_=1):
    return SimpleNamespace(id=id_, vendor=vendor, product=product)


def _aff(vendor, product):
    return [{'vendor': vendor, 'product': product}]


# ============================================================================ CASADO

class TestTokens:
    def test_normaliza_y_quita_formas_juridicas(self):
        assert tokens('Oracle Corporation') == ['oracle'] and tokens('Acme, Inc.') == ['acme']
        assert tokens('Log4j2') == ['log4j2'] and tokens('IOS XE Software') == ['ios', 'xe']     # 'software' es palabra vacía

    @pytest.mark.parametrize('v', [None, '', '  ', 'n/a', 'N/A', 'unknown', '-', 'none'])
    def test_no_informativos(self, v):
        assert tokens(v) == []


class TestCasado:
    @pytest.mark.parametrize('ev,ep,av,ap,esperado', [
        ('Apache', 'Log4j', 'Apache', 'Log4j2', True),            # el CVE añade dígitos de versión
        ('Apache', 'Log4j2', 'Apache', 'Log4j', False),           # al revés no: la entrada es MÁS específica
        (None, 'Go', 'Google', 'Chrome', False),                  # 'go' NO casa 'google' (nunca por subcadena)
        (None, 'Go', 'Go', 'Go', True),
        ('Go', None, 'Google', 'Chrome', False),
        ('Cisco', None, 'Cisco', 'IOS XE Software', True),        # solo vendor: todos sus productos
        (None, 'Exchange Server', 'Microsoft', 'Exchange Server', True),     # solo producto: cualquier vendor
        ('Microsoft', 'Windows', 'Microsoft', 'Windows CNG Key Isolation Service', True),   # tokens superset
        ('Microsoft', 'Windows', 'Apple', 'Windows', False),      # el vendor declarado restringe
        ('Oracle', None, 'Oracle Corporation', 'Mobile Field Service', True),  # forma jurídica ignorada
        ('Red Hat', None, 'Red Hat', 'Enterprise Linux', True),
        ('Red Hat', None, 'Red', 'Hat Foo', False),               # el vendor del CVE debe contener TODOS los tokens
        ('Linux', 'Kernel', 'Linux', 'Kernel', True),
        ('Linux', 'Kernel', 'Red Hat', 'Enterprise Linux', False),
        ('Fortinet', 'FortiOS', 'Fortinet', 'FortiOS and FortiProxy SSL-VPN', True),
        ('Fortinet', 'FortiOS', 'Fortinet', 'FortiGate', False),
        ('cisco', 'ios xe', 'Cisco', 'IOS XE Web UI', True),      # sin distinguir mayúsculas
    ])
    def test_tabla(self, ev, ep, av, ap, esperado):
        assert entry_matches(ev, ep, _aff(av, ap)) is esperado

    def test_basta_un_par_afectado_de_varios(self):
        aff = [{'vendor': 'Apple', 'product': 'iOS'}, {'vendor': 'Cisco', 'product': 'IOS XE'}]
        assert entry_matches('Cisco', 'IOS', aff) is True

    def test_limite_documentado_entrada_solo_de_producto_casa_varios_vendors(self):
        """'IOS' sin vendor casa Cisco IOS y Apple iOS: por eso la UI recomienda declarar el vendor."""
        assert entry_matches(None, 'IOS', _aff('Apple', 'iOS')) and entry_matches(None, 'IOS', _aff('Cisco', 'IOS XE'))
        assert not entry_matches('Cisco', 'IOS', _aff('Apple', 'iOS'))                 # control: con vendor se desambigua

    @pytest.mark.parametrize('v,p', [(None, None), ('', ''), ('Inc', None), ('Corporation', 'Inc'), ('n/a', None)])
    def test_entrada_sin_tokens_informativos_no_casa_con_nada(self, v, p):
        """Si no, una entrada vacía casaría TODO."""
        assert not entry_is_valid(v, p)
        assert not entry_matches(v, p, _aff('Cisco', 'IOS'))

    @pytest.mark.parametrize('aff', [None, [], [{}], [{'vendor': None, 'product': None}], [{'vendor': 'n/a', 'product': 'n/a'}]])
    def test_cve_sin_afectados_utiles_no_casa(self, aff):
        assert not entry_matches('Cisco', None, aff)

    def test_match_entries_devuelve_ids(self):
        es = [_entry('Cisco', None, 7), _entry('Fortinet', None, 8), _entry(None, 'IOS', 9)]
        assert match_entries(es, _aff('Cisco', 'IOS XE')) == [7, 9]
        assert match_entries([], _aff('Cisco', 'IOS XE')) == []

    def test_contra_el_catalogo_kev_real(self):
        """Sobre 34 entradas reales de KEV: lo esperado casa y lo que no, no."""
        kev = _j('kev_sample.json')['vulnerabilities']
        aff = lambda v: _aff(v['vendorProject'], v['product'])
        by = lambda pred: [v['cveID'] for v in kev if pred(v)]
        log4j = by(lambda v: entry_matches('Apache', 'Log4j', aff(v)))
        assert log4j and all('Log4j' in next(k for k in kev if k['cveID'] == c)['product'] for c in log4j)
        assert not by(lambda v: entry_matches(None, 'Go', aff(v)))                          # 0 falsos positivos de 'go'
        forti = by(lambda v: entry_matches('Fortinet', 'FortiOS', aff(v)))
        assert forti and all(next(k for k in kev if k['cveID'] == c)['vendorProject'] == 'Fortinet' for c in forti)
        assert by(lambda v: entry_matches('Microsoft', None, aff(v))) and not any(
            next(k for k in kev if k['cveID'] == c)['vendorProject'] != 'Microsoft'
            for c in by(lambda v: entry_matches('Microsoft', None, aff(v))))


# ============================================================================ FUENTES

class TestFetchKev:
    def _fetch(self, since, payload=None):
        with patch.object(cve_clients, 'http_get', return_value=_resp(200, payload or _j('kev_sample.json'))):
            return fetch_kev(since)

    def test_filtra_por_fecha_de_alta(self, app_ctx):
        todos = self._fetch(date(2000, 1, 1))
        recientes = self._fetch(date(2026, 10, 20))
        assert len(todos) == 34 and 0 < len(recientes) < len(todos)
        assert all(i['kev_date_added'] >= date(2026, 10, 20) for i in recientes)

    def test_campos_normalizados(self, app_ctx):
        i = next(x for x in self._fetch(date(2000, 1, 1)) if x['cve_id'] == 'CVE-2021-44228' or x['affected'][0]['product'] == 'Log4j2')
        assert i['source'] == 'cisa_kev' and i['in_kev'] is True and i['title'] and i['summary']
        assert i['affected'] == [{'vendor': 'Apache', 'product': 'Log4j2'}] and i['published_at'].year >= 2021
        assert i['cvss_score'] is None and i['epss'] is None

    def test_ransomware_conocido(self, app_ctx):
        its = self._fetch(date(2000, 1, 1))
        assert any(i['known_ransomware'] for i in its) and any(not i['known_ransomware'] for i in its)

    def test_error_de_red_es_feederror(self, app_ctx):
        with patch.object(cve_clients, 'http_get', return_value=_resp(503)):
            with pytest.raises(FeedError):
                fetch_kev(date(2026, 1, 1))

    def test_forma_inesperada_es_feederror_no_cero_novedades(self, app_ctx):
        """Un 200 con otra forma NO es 'sin novedades'."""
        with patch.object(cve_clients, 'http_get', return_value=_resp(200, {'otra': 'cosa'})):
            with pytest.raises(FeedError):
                fetch_kev(date(2026, 1, 1))


class TestFetchNvd:
    def _call(self, responses, key=None, app=None):
        sleeps = []
        with patch.object(feed_sources, 'http_get', side_effect=list(responses)) as g:
            if key and app:
                app.config['API_KEYS']['nvd'] = key
            try:
                out = fetch_nvd_recent(NOW - timedelta(days=2), NOW, sleep=sleeps.append)
            finally:
                if app:
                    app.config['API_KEYS']['nvd'] = None
        return out, sleeps, g

    def test_parsea_la_respuesta_real(self, app_ctx):
        real = _resp(200, _j('nvd_recent_sample.json'))
        out, _, _ = self._call([real, _resp(200, {'totalResults': 0, 'vulnerabilities': []})])
        assert len(out) == 8
        i = next(x for x in out if x['cve_id'] == 'CVE-2026-101691')
        assert i['source'] == 'nvd_recent' and i['in_kev'] is False and i['cvss_score'] is not None
        assert {'vendor': 'Oracle Corporation', 'product': 'Oracle Mobile Field Service'} in i['affected']
        assert i['title'].startswith('Vulnerability in the Oracle') and i['published_at'].year == 2026

    def test_pide_critical_y_high_con_la_ventana(self, app_ctx):
        _, _, g = self._call([_resp(200, {'totalResults': 0, 'vulnerabilities': []})] * 2)
        sev = [c.kwargs['params']['cvssV3Severity'] for c in g.call_args_list]
        assert sev == ['CRITICAL', 'HIGH']
        p = g.call_args_list[0].kwargs['params']
        assert p['pubStartDate'] == '2026-11-17T12:00:00.000' and p['pubEndDate'] == '2026-11-19T12:00:00.000'

    def test_espacia_las_peticiones_segun_la_clave(self, app, app_ctx):
        empty = _resp(200, {'totalResults': 0, 'vulnerabilities': []})
        _, sleeps, _ = self._call([empty, empty])
        assert sleeps == [7.0]                                  # sin clave: 5 peticiones / 30 s
        _, sleeps, g = self._call([empty, empty], key='k', app=app)
        assert sleeps == [1.0] and g.call_args.kwargs['headers'] == {'apiKey': 'k'}

    def test_la_ventana_se_acota_a_120_dias(self, app_ctx):
        with patch.object(feed_sources, 'http_get', return_value=_resp(200, {'totalResults': 0, 'vulnerabilities': []})) as g:
            fetch_nvd_recent(NOW - timedelta(days=400), NOW, sleep=lambda s: None)
        start = datetime.strptime(g.call_args_list[0].kwargs['params']['pubStartDate'], '%Y-%m-%dT%H:%M:%S.000')
        assert NOW - start <= timedelta(days=120)

    def test_pagina_si_hay_mas_de_una_pagina(self, app_ctx):
        real = _j('nvd_recent_sample.json')
        p1 = dict(real, totalResults=3000)                       # 3000 > 2000: pide la 2.ª página
        p2 = dict(real, totalResults=3000, vulnerabilities=[])
        out, _, g = self._call([_resp(200, p1), _resp(200, p2), _resp(200, {'totalResults': 0, 'vulnerabilities': []})])
        assert [c.kwargs['params']['startIndex'] for c in g.call_args_list][:2] == [0, 2000]

    def test_un_cve_en_critical_y_high_no_se_duplica(self, app_ctx):
        real = _resp(200, _j('nvd_recent_sample.json'))
        out, _, _ = self._call([real, real])
        assert len(out) == 8

    @pytest.mark.parametrize('resp', [_resp(429), _resp(403), _resp(500), _resp(200, json_error=True),
                                      _resp(200, {'foo': 1}), _resp(200, {'vulnerabilities': 'x', 'totalResults': 1}),
                                      _resp(200, {'vulnerabilities': [{'sin': 'cve'}], 'totalResults': 1})])
    def test_fallos_y_formas_inesperadas_son_feederror(self, app_ctx, resp):
        with pytest.raises(FeedError):
            self._call([resp])

    def test_excepcion_de_red(self, app_ctx):
        with patch.object(feed_sources, 'http_get', side_effect=OSError('sin red')):
            with pytest.raises(FeedError):
                fetch_nvd_recent(NOW - timedelta(days=1), NOW, sleep=lambda s: None)

    def test_pares_no_informativos_se_descartan(self, app_ctx):
        real = _j('nvd_recent_sample.json')
        cve = real['vulnerabilities'][0]['cve']
        cve['affected'] = [{'source': 's', 'affectedData': [{'vendor': 'n/a', 'product': 'n/a'}, {'vendor': 'Acme', 'product': 'Foo'}]}]
        out, _, _ = self._call([_resp(200, dict(real, vulnerabilities=[{'cve': cve}], totalResults=1)),
                                _resp(200, {'totalResults': 0, 'vulnerabilities': []})])
        assert out[0]['affected'] == [{'vendor': 'Acme', 'product': 'Foo'}]


class TestFetchEpss:
    def test_lote_real_devuelve_solo_los_puntuados(self):
        real = _j('epss_batch.json')
        with patch.object(feed_sources, 'http_get', return_value=_resp(200, real)):
            r = fetch_epss(['CVE-A', 'CVE-B'])
        assert len(r) == len(real['data']) == 1 and all(0 <= v <= 1 for v in r.values())

    def test_fallo_no_lanza_y_devuelve_lo_obtenido(self):
        with patch.object(feed_sources, 'http_get', side_effect=OSError('x')):
            assert fetch_epss(['CVE-2026-1']) == {}
        with patch.object(feed_sources, 'http_get', return_value=_resp(500)):
            assert fetch_epss(['CVE-2026-1']) == {}

    def test_trocea_en_lotes(self):
        with patch.object(feed_sources, 'http_get', return_value=_resp(200, {'data': []})) as g:
            fetch_epss([f'CVE-2026-{i}' for i in range(120)])
        assert g.call_count == 3 and all(len(c.kwargs['params']['cve'].split(',')) <= 50 for c in g.call_args_list)

    def test_filas_malformadas_se_ignoran(self):
        with patch.object(feed_sources, 'http_get', return_value=_resp(200, {'data': [{'cve': 'CVE-1'}, {'cve': 'CVE-2', 'epss': 'x'},
                                                                                       {'cve': 'cve-3', 'epss': '0.5'}]})):
            assert fetch_epss(['a']) == {'CVE-3': 0.5}


# ============================================================================ EJECUTOR

def _item(cve='CVE-2026-1', source='nvd_recent', **kw):
    base = {'cve_id': cve, 'title': 't', 'summary': 's', 'published_at': NOW - timedelta(hours=3), 'source': source,
            'affected': _aff('Cisco', 'IOS XE'), 'in_kev': False, 'kev_date_added': None, 'known_ransomware': False,
            'cvss_score': 9.8, 'epss': None}
    base.update(kw)
    return base


def _stack(db_session, *pairs):
    out = []
    for v, p in pairs:
        e = TechStackEntry(vendor=v, product=p)
        db_session.session.add(e)
        out.append(e)
    db_session.session.commit()
    return out


class TestUpsert:
    def test_nuevo_y_casa_con_el_stack(self, app, db_session):
        entries = _stack(db_session, ('Cisco', None))
        r = feed_runner.upsert_item(_item(), entries, NOW)
        db_session.session.commit()
        i = FeedItem.query.one()
        assert r == {'created': True, 'escalated': False, 'alert': True}
        assert i.is_relevant and i.matched_entries == [entries[0].id] and i.sources == ['nvd_recent']

    def test_nuevo_sin_casar_no_alerta(self, app, db_session):
        entries = _stack(db_session, ('Fortinet', None))
        r = feed_runner.upsert_item(_item(), entries, NOW)
        assert r['alert'] is False and FeedItem.query.one().is_relevant is False

    def test_idempotente(self, app, db_session):
        entries = _stack(db_session, ('Cisco', None))
        feed_runner.upsert_item(_item(), entries, NOW)
        db_session.session.commit()
        r = feed_runner.upsert_item(_item(), entries, NOW + timedelta(hours=1))
        db_session.session.commit()
        assert FeedItem.query.count() == 1 and r == {'created': False, 'escalated': False, 'alert': False}

    def test_escalado_a_kev_alerta_aunque_ya_se_conociera(self, app, db_session):
        entries = _stack(db_session, ('Cisco', None))
        feed_runner.upsert_item(_item(), entries, NOW)
        db_session.session.commit()
        kev = _item(source='cisa_kev', in_kev=True, kev_date_added=date(2026, 11, 19), cvss_score=None, known_ransomware=True)
        r = feed_runner.upsert_item(kev, entries, NOW + timedelta(days=1))
        db_session.session.commit()
        i = FeedItem.query.one()
        assert r['escalated'] and r['alert'] and i.in_kev and i.escalated_at and i.known_ransomware
        assert sorted(i.sources) == ['cisa_kev', 'nvd_recent'] and i.cvss_score == 9.8      # no pierde el CVSS de NVD

    def test_kev_que_llega_primero_no_cuenta_como_escalado(self, app, db_session):
        r = feed_runner.upsert_item(_item(source='cisa_kev', in_kev=True, kev_date_added=date(2026, 11, 19)), [], NOW)
        assert r['created'] and not r['escalated'] and FeedItem.query.one().escalated_at is None

    def test_vuelve_a_alertar_si_pasa_a_casar_por_afectados_nuevos(self, app, db_session):
        entries = _stack(db_session, ('Cisco', None))
        feed_runner.upsert_item(_item(affected=_aff('Acme', 'Foo')), entries, NOW)
        db_session.session.commit()
        assert not FeedItem.query.one().is_relevant
        r = feed_runner.upsert_item(_item(), entries, NOW)               # la CNA añade Cisco después
        assert r['alert'] and len(FeedItem.query.one().affected) == 2

    def test_la_fecha_publicada_es_la_mas_temprana_y_no_se_machaca_el_titulo(self, app, db_session):
        feed_runner.upsert_item(_item(title='original'), [], NOW)
        feed_runner.upsert_item(_item(title='otro', published_at=NOW - timedelta(days=5)), [], NOW)
        db_session.session.commit()
        i = FeedItem.query.one()
        assert i.published_at == NOW - timedelta(days=5) and i.title == 'original'

    def test_epss_none_no_pisa_un_valor_conocido(self, app, db_session):
        feed_runner.upsert_item(_item(epss=0.7), [], NOW)
        feed_runner.upsert_item(_item(epss=None), [], NOW)
        db_session.session.commit()
        assert FeedItem.query.one().epss == 0.7


class TestPrioridad:
    @pytest.mark.parametrize('kw,nivel_min', [
        (dict(in_kev=True, cvss_score=None, epss=None), 'ALTO'),       # el SUELO: antes quedaba en MEDIO (40)
        (dict(in_kev=True, known_ransomware=True, cvss_score=None), 'ALTO'),
        (dict(in_kev=True, cvss_score=9.8, epss=0.9), 'CRÍTICO'),
    ])
    def test_kev_es_alto_como_minimo(self, app, db_session, kw, nivel_min):
        order = ['LIMPIO', 'BAJO', 'MEDIO', 'ALTO', 'CRÍTICO']
        feed_runner.upsert_item(_item(source='cisa_kev', kev_date_added=date(2026, 11, 19), **kw), [], NOW)
        db_session.session.commit()
        assert order.index(FeedItem.query.one().risk_level) >= order.index(nivel_min)

    def test_control_sin_kev_no_tiene_suelo(self, app, db_session):
        feed_runner.upsert_item(_item(cvss_score=7.5), [], NOW)
        db_session.session.commit()
        i = FeedItem.query.one()
        assert i.priority_score == 20 and i.risk_level == 'BAJO'

    def test_usa_las_mismas_reglas_que_el_analisis_de_un_cve(self, app, db_session):
        """Una sola definición de 'peligroso': la del análisis (LLMOrchestrator._cve_points)."""
        from app.services.llm_orchestrator import LLMOrchestrator as L
        feed_runner.upsert_item(_item(cvss_score=9.8, epss=0.6), [], NOW)
        db_session.session.commit()
        esperado = L._cve_points('nvd', {'found': True, 'cvss_score': 9.8}) + L._cve_points('epss', {'epss': 0.6})
        assert FeedItem.query.one().priority_score == esperado == 60

    def test_tope_100(self, app, db_session):
        feed_runner.upsert_item(_item(source='cisa_kev', in_kev=True, known_ransomware=True, cvss_score=10, epss=0.99,
                                      kev_date_added=date(2026, 11, 19)), [], NOW)
        db_session.session.commit()
        assert FeedItem.query.one().priority_score == 100


class TestRecompute:
    def test_cambia_la_relevancia_al_cambiar_el_stack(self, app, db_session):
        feed_runner.upsert_item(_item(), [], NOW)
        db_session.session.commit()
        assert not FeedItem.query.one().is_relevant
        _stack(db_session, ('Cisco', None))
        assert feed_runner.recompute_relevance() == {'changed': 1, 'relevant': 1}
        assert FeedItem.query.one().is_relevant
        TechStackEntry.query.delete()
        db_session.session.commit()
        assert feed_runner.recompute_relevance() == {'changed': 1, 'relevant': 0}
        assert not FeedItem.query.one().is_relevant


class TestRunSource:
    def _fetchers(self, items=None, boom=None):
        def f(since, now):
            f.calls.append((since, now))
            if boom:
                raise boom
            return list(items or [])
        f.calls = []
        return f

    def test_ejecucion_ok_registra_feedrun_y_resumen(self, app, db_session):
        _stack(db_session, ('Cisco', None))
        f = self._fetchers([_item('CVE-2026-1'), _item('CVE-2026-2', affected=_aff('Acme', 'X'))])
        r = feed_runner.run_source('nvd_recent', now=NOW, fetchers={'nvd_recent': f}, enrich_epss=False)
        run = FeedRun.query.one()
        assert r['status'] == 'ok' and r['fetched'] == 2 and r['new'] == 2 and r['alerts'] == 1
        assert (run.status, run.fetched, run.new_items, run.relevant_new) == ('ok', 2, 2, 1) and run.finished_at

    def test_segunda_ejecucion_no_duplica_ni_alerta(self, app, db_session):
        _stack(db_session, ('Cisco', None))
        f = self._fetchers([_item()])
        feed_runner.run_source('nvd_recent', now=NOW, fetchers={'nvd_recent': f}, enrich_epss=False)
        r = feed_runner.run_source('nvd_recent', now=NOW + timedelta(hours=7), fetchers={'nvd_recent': f}, enrich_epss=False)
        assert FeedItem.query.count() == 1 and (r['new'], r['updated'], r['alerts']) == (0, 1, 0)

    def test_primera_ejecucion_mira_atras_lo_configurado_y_las_siguientes_desde_la_ultima(self, app, db_session):
        f = self._fetchers([])
        feed_runner.run_source('nvd_recent', now=NOW, fetchers={'nvd_recent': f}, enrich_epss=False)
        feed_runner.run_source('nvd_recent', now=NOW + timedelta(hours=7), fetchers={'nvd_recent': f}, enrich_epss=False)
        spec = feed_runner.SOURCES['nvd_recent']
        assert f.calls[0][0] == NOW - spec.first_lookback
        assert f.calls[1][0] == NOW - spec.overlap                          # desde la última OK, con solapamiento

    def test_lookback_explicito_manda(self, app, db_session):
        f = self._fetchers([])
        feed_runner.run_source('cisa_kev', now=NOW, lookback=timedelta(days=90), fetchers={'cisa_kev': f}, enrich_epss=False)
        assert f.calls[0][0] == NOW - timedelta(days=90)

    def test_un_error_se_registra_sin_dejar_datos_a_medias(self, app, db_session):
        f = self._fetchers(boom=FeedError('NVD HTTP 429: límite'))
        r = feed_runner.run_source('nvd_recent', now=NOW, fetchers={'nvd_recent': f}, enrich_epss=False)
        run = FeedRun.query.one()
        assert r['status'] == 'error' and 'límite' in r['error'] and run.status == 'error' and 'límite' in run.error
        assert FeedItem.query.count() == 0

    def test_un_fallo_a_mitad_revierte_lo_ya_insertado(self, app, db_session):
        _stack(db_session, ('Cisco', None))                                  # sin stack no se evaluaría el casado
        bad = _item('CVE-2026-9', affected='no-es-una-lista')                # revienta dentro del upsert
        f = self._fetchers([_item('CVE-2026-1'), bad])
        r = feed_runner.run_source('nvd_recent', now=NOW, fetchers={'nvd_recent': f}, enrich_epss=False)
        assert r['status'] == 'error' and FeedItem.query.count() == 0       # ni siquiera el primero queda

    def test_un_error_no_cuenta_como_ultima_ok(self, app, db_session):
        feed_runner.run_source('nvd_recent', now=NOW, fetchers={'nvd_recent': self._fetchers(boom=FeedError('x'))}, enrich_epss=False)
        assert feed_runner.last_ok_run('nvd_recent') is None
        assert feed_runner.is_due('nvd_recent', NOW + feed_runner.ERROR_BACKOFF)        # pasada la espera, vuelve a intentarse

    def test_enriquece_con_epss_y_deja_none_a_los_no_puntuados(self, app, db_session):
        f = self._fetchers([_item('CVE-2026-1'), _item('CVE-2026-2')])
        with patch.object(feed_sources, 'fetch_epss', return_value={'CVE-2026-1': 0.8}) as e:
            feed_runner.run_source('nvd_recent', now=NOW, fetchers={'nvd_recent': f})
        assert sorted(e.call_args.args[0]) == ['CVE-2026-1', 'CVE-2026-2']
        assert FeedItem.query.filter_by(cve_id='CVE-2026-1').one().epss == 0.8
        assert FeedItem.query.filter_by(cve_id='CVE-2026-2').one().epss is None

    def test_fuente_desconocida(self, app, db_session):
        with pytest.raises(KeyError):
            feed_runner.run_source('inventada', now=NOW)


class TestBloqueo:
    def test_otra_instancia_ejecutando_la_misma_fuente_se_salta(self, app, db_session):
        """Advisory lock: el daemon y un `flask feeds run` a mano no pisan la misma fuente."""
        other = db.engine.connect()
        try:
            assert other.execute(text('SELECT pg_try_advisory_lock(:k)'), {'k': feed_runner._lock_key('nvd_recent')}).scalar()
            f = lambda since, now: [_item()]
            r = feed_runner.run_source('nvd_recent', now=NOW, fetchers={'nvd_recent': f}, enrich_epss=False)
            assert r['status'] == 'skipped' and FeedRun.query.count() == 0 and FeedItem.query.count() == 0
            # control: otra fuente NO está bloqueada
            assert feed_runner.run_source('cisa_kev', now=NOW, fetchers={'cisa_kev': lambda s, n: []}, enrich_epss=False)['status'] == 'ok'
        finally:
            other.execute(text('SELECT pg_advisory_unlock(:k)'), {'k': feed_runner._lock_key('nvd_recent')})
            other.close()

    def test_el_lock_se_libera_al_terminar_incluso_con_error(self, app, db_session):
        feed_runner.run_source('nvd_recent', now=NOW, fetchers={'nvd_recent': lambda s, n: (_ for _ in ()).throw(FeedError('x'))},
                               enrich_epss=False)
        r = feed_runner.run_source('nvd_recent', now=NOW, fetchers={'nvd_recent': lambda s, n: []}, enrich_epss=False)
        assert r['status'] == 'ok'

    def test_claves_de_lock_distintas_por_fuente_y_estables(self):
        assert feed_runner._lock_key('cisa_kev') != feed_runner._lock_key('nvd_recent')
        assert feed_runner._lock_key('cisa_kev') == feed_runner._lock_key('cisa_kev')


class TestVencidas:
    def test_nunca_corrio_esta_vencida(self, app, db_session):
        assert feed_runner.is_due('cisa_kev', NOW)

    def test_ok_reciente_no_vence_y_pasado_el_intervalo_si(self, app, db_session):
        feed_runner.run_source('cisa_kev', now=NOW, fetchers={'cisa_kev': lambda s, n: []}, enrich_epss=False)
        iv = feed_runner.SOURCES['cisa_kev'].interval
        assert not feed_runner.is_due('cisa_kev', NOW + iv - timedelta(minutes=1))
        assert feed_runner.is_due('cisa_kev', NOW + iv)

    def test_run_due_solo_ejecuta_las_vencidas_y_un_fallo_no_impide_las_demas(self, app, db_session):
        feed_runner.run_source('cisa_kev', now=NOW, fetchers={'cisa_kev': lambda s, n: []}, enrich_epss=False)
        later = NOW + timedelta(hours=1)
        res = feed_runner.run_due(now=later, fetchers={'nvd_recent': lambda s, n: [_item()]}, enrich_epss=False)
        assert [r['source'] for r in res] == ['nvd_recent']                 # KEV no venció
        much_later = NOW + timedelta(days=2)
        boom = lambda s, n: (_ for _ in ()).throw(FeedError('KEV caído'))
        res = feed_runner.run_due(now=much_later, fetchers={'cisa_kev': boom, 'nvd_recent': lambda s, n: []}, enrich_epss=False)
        assert {r['source']: r['status'] for r in res} == {'cisa_kev': 'error', 'nvd_recent': 'ok'}


class TestDaemon:
    def test_ejecuta_lo_vencido_en_cada_ciclo_y_duerme_poll(self, app, db_session):
        sleeps, ciclos = [], {'n': 0}

        def stop():
            return ciclos['n'] >= 2

        def sleep(s):
            sleeps.append(s)
            ciclos['n'] += 1

        with patch.object(feed_runner, 'run_due', return_value=[]) as rd:
            feed_runner.daemon(poll_seconds=42, stop=stop, sleep=sleep)
        assert rd.call_count == 2 and sleeps == [42, 42]

    def test_un_ciclo_que_falla_no_mata_el_daemon(self, app, db_session):
        ciclos = {'n': 0}
        with patch.object(feed_runner, 'run_due', side_effect=[RuntimeError('boom'), []]) as rd:
            feed_runner.daemon(poll_seconds=1, stop=lambda: ciclos['n'] >= 2,
                               sleep=lambda s: ciclos.__setitem__('n', ciclos['n'] + 1))
        assert rd.call_count == 2


# ============================================================================ API

BASE = '/api/v2/feeds'


def _usuario_y_cliente(app, db_session, username, role):
    u = User(username=username, email=f'{username}@soc-test.local', role=role, is_active=True)
    u.password_hash = 'x'
    db_session.session.add(u)
    db_session.session.commit()
    c = app.test_client()
    with c.session_transaction() as s:
        s['_user_id'] = str(u.id)
        s['_fresh'] = True
    return c


@pytest.fixture
def senior(app, db_session):
    return _usuario_y_cliente(app, db_session, 'fd_senior', 'senior_analyst')


@pytest.fixture
def viewer(app, db_session):
    return _usuario_y_cliente(app, db_session, 'fd_viewer', 'viewer')


def _carga(db_session, entries):
    for i in (_item('CVE-2026-1', cvss_score=9.8, epss=0.6), _item('CVE-2026-2', cvss_score=7.5),
              _item('CVE-2026-3', affected=_aff('Acme', 'Foo'), cvss_score=9.9),
              _item('CVE-2026-4', source='cisa_kev', in_kev=True, kev_date_added=date(2026, 11, 18), cvss_score=None,
                    affected=_aff('Cisco', 'BroadWorks'))):
        feed_runner.upsert_item(i, entries, utcnow_())
    db_session.session.commit()


def utcnow_():
    from app.utils.time_utils import utcnow
    return utcnow()


class TestApiItems:
    def test_por_defecto_solo_relevantes_ordenados_por_prioridad(self, app, db_session, analyst_client):
        entries = _stack(db_session, ('Cisco', None))
        _carga(db_session, entries)
        d = analyst_client.get(f'{BASE}/items').get_json()
        # por prioridad: CVSS 9.8 + EPSS 0.6 = 60 > KEV sin CVSS (suelo 50) > CVSS 7.5 = 20
        assert d['total'] == 3 and [i['cve_id'] for i in d['items']] == ['CVE-2026-1', 'CVE-2026-4', 'CVE-2026-2']
        assert d['items'][0]['matched_labels'] == ['Cisco'] and d['items'][0]['risk_level'] == 'ALTO'
        assert d['items'][1]['in_kev'] is True and d['items'][1]['risk_level'] == 'ALTO'

    def test_relevant_0_muestra_todos_y_el_control_cambia_el_total(self, app, db_session, analyst_client):
        _carga(db_session, _stack(db_session, ('Cisco', None)))
        assert analyst_client.get(f'{BASE}/items?relevant=0').get_json()['total'] == 4

    def test_sin_stack_nada_es_relevante(self, app, db_session, analyst_client):
        _carga(db_session, [])
        d = analyst_client.get(f'{BASE}/items').get_json()
        assert d['total'] == 0 and analyst_client.get(f'{BASE}/items?relevant=0').get_json()['total'] == 4

    def test_filtro_de_riesgo_minimo(self, app, db_session, analyst_client):
        _carga(db_session, _stack(db_session, ('Cisco', None)))
        alto = analyst_client.get(f'{BASE}/items?relevant=0&risk=ALTO').get_json()
        assert all(i['risk_level'] in ('ALTO', 'CRÍTICO') for i in alto['items']) and 0 < alto['total'] < 4
        assert analyst_client.get(f'{BASE}/items?risk=NADA').status_code == 400

    def test_ventana_de_dias_y_paginacion(self, app, db_session, analyst_client):
        _carga(db_session, _stack(db_session, ('Cisco', None)))
        FeedItem.query.filter_by(cve_id='CVE-2026-2').update({'first_seen_at': utcnow_() - timedelta(days=40)})
        db_session.session.commit()
        assert analyst_client.get(f'{BASE}/items?days=30').get_json()['total'] == 2
        assert analyst_client.get(f'{BASE}/items?days=90').get_json()['total'] == 3
        pag1 = analyst_client.get(f'{BASE}/items?relevant=0&limit=2').get_json()
        pag2 = analyst_client.get(f'{BASE}/items?relevant=0&limit=2&offset=2').get_json()
        assert pag1['total'] == pag2['total'] == 3 and (pag1['count'], pag2['count']) == (2, 1)
        assert not {i['cve_id'] for i in pag1['items']} & {i['cve_id'] for i in pag2['items']}       # sin solapamiento

    @pytest.mark.parametrize('qs', ['days=abc', 'limit=-5', 'limit=99999', 'offset=-1', 'days=0'])
    def test_parametros_absurdos_se_acotan_sin_romper(self, app, db_session, analyst_client, qs):
        assert analyst_client.get(f'{BASE}/items?{qs}').status_code == 200

    def test_anonimo_no_accede(self, client):
        for path in ('/items', '/status', '/stack'):
            assert client.get(BASE + path).status_code in (302, 401)

    def test_viewer_puede_leer(self, app, db_session, viewer):
        assert viewer.get(f'{BASE}/items').status_code == 200 and viewer.get(f'{BASE}/stack').status_code == 200


class TestApiStatus:
    def test_sin_ejecuciones_esta_vencida(self, app, db_session, analyst_client):
        d = analyst_client.get(f'{BASE}/status').get_json()
        assert {s['source'] for s in d['sources']} == {'cisa_kev', 'nvd_recent'}
        assert all(s['stale'] and s['lag_minutes'] is None and s['last_ok'] is None for s in d['sources'])

    def test_tras_una_ejecucion_no_esta_vencida(self, app, db_session, analyst_client):
        for n in ('cisa_kev', 'nvd_recent'):
            feed_runner.run_source(n, now=utcnow_(), fetchers={n: lambda s, now: []}, enrich_epss=False)
        d = analyst_client.get(f'{BASE}/status').get_json()
        assert all(not s['stale'] and s['lag_minutes'] <= 1 for s in d['sources'])

    def test_stale_si_pasaron_mas_de_dos_intervalos(self, app, db_session, analyst_client):
        feed_runner.run_source('cisa_kev', now=utcnow_() - timedelta(hours=13), fetchers={'cisa_kev': lambda s, n: []}, enrich_epss=False)
        d = analyst_client.get(f'{BASE}/status').get_json()
        assert next(s for s in d['sources'] if s['source'] == 'cisa_kev')['stale'] is True      # 13 h > 2 × 6 h

    def test_contadores(self, app, db_session, analyst_client):
        _carga(db_session, _stack(db_session, ('Cisco', None)))
        d = analyst_client.get(f'{BASE}/status').get_json()
        assert (d['stack_size'], d['items_total'], d['relevant_total'], d['relevant_last_7d']) == (1, 4, 3, 3)


class TestApiStack:
    def test_senior_anade_y_se_recalcula_la_relevancia(self, app, db_session, senior, analyst_client):
        _carga(db_session, [])
        r = senior.post(f'{BASE}/stack', json={'vendor': 'Cisco'})
        assert r.status_code == 201 and r.get_json()['relevance']['relevant'] == 3
        assert AuditEvent.query.filter_by(action='feed_stack_added').count() == 1

    def test_borrar_quita_la_relevancia(self, app, db_session, senior):
        _carga(db_session, _stack(db_session, ('Cisco', None)))
        eid = TechStackEntry.query.one().id
        r = senior.delete(f'{BASE}/stack/{eid}')
        assert r.status_code == 200 and r.get_json()['relevance']['relevant'] == 0
        assert AuditEvent.query.filter_by(action='feed_stack_removed').count() == 1

    @pytest.mark.parametrize('rol', ['viewer', 'analyst'])
    def test_roles_bajos_no_modifican_el_stack(self, app, db_session, rol):
        c = _usuario_y_cliente(app, db_session, f'fd_{rol}', rol)
        e = _stack(db_session, ('Cisco', None))[0]
        assert c.post(f'{BASE}/stack', json={'vendor': 'Fortinet'}).status_code == 403
        assert c.delete(f'{BASE}/stack/{e.id}').status_code == 403
        assert TechStackEntry.query.count() == 1

    def test_admin_si(self, app, db_session, admin_client):
        assert admin_client.post(f'{BASE}/stack', json={'product': 'Exchange Server'}).status_code == 201

    @pytest.mark.parametrize('body', [{}, {'vendor': ''}, {'vendor': '   ', 'product': ''}, {'vendor': 'Inc'}, {'vendor': 'n/a'},
                                      {'vendor': 5}, {'vendor': 'x' * 121}, {'vendor': 'Cisco', 'note': 'n' * 301}, None])
    def test_entradas_invalidas_400(self, app, db_session, senior, body):
        r = senior.post(f'{BASE}/stack', json=body)
        assert r.status_code == 400 and TechStackEntry.query.count() == 0

    def test_duplicado_409_sin_distinguir_mayusculas(self, app, db_session, senior):
        assert senior.post(f'{BASE}/stack', json={'vendor': 'Cisco', 'product': 'IOS'}).status_code == 201
        assert senior.post(f'{BASE}/stack', json={'vendor': 'CISCO', 'product': 'ios'}).status_code == 409

    def test_control_vendor_solo_y_vendor_mas_producto_son_distintas(self, app, db_session, senior):
        assert senior.post(f'{BASE}/stack', json={'vendor': 'Cisco'}).status_code == 201
        assert senior.post(f'{BASE}/stack', json={'vendor': 'Cisco', 'product': 'IOS'}).status_code == 201

    def test_borrar_inexistente_404(self, app, db_session, senior):
        assert senior.delete(f'{BASE}/stack/999999').status_code == 404

    def test_limite_de_entradas(self, app, db_session, senior):
        db_session.session.add_all([TechStackEntry(vendor=f'v{i}') for i in range(200)])
        db_session.session.commit()
        assert senior.post(f'{BASE}/stack', json={'vendor': 'uno mas'}).status_code == 409


# ============================================================================ UI

class TestUi:
    def test_pagina_cumple_la_csp(self, analyst_client):
        r = analyst_client.get('/feeds')
        html = r.get_data(as_text=True)
        assert r.status_code == 200 and 'Feeds de CVEs' in html
        assert 'onclick=' not in html and 'onchange=' not in html and '<script nonce=' in html

    def test_el_formulario_del_stack_solo_para_senior_y_admin(self, analyst_client, admin_client):
        assert 'id="stVendor"' not in analyst_client.get('/feeds').get_data(as_text=True)
        assert 'id="stVendor"' in admin_client.get('/feeds').get_data(as_text=True)

    def test_enlace_lateral_y_anonimo(self, analyst_client, client):
        assert '/feeds' in analyst_client.get('/dashboard').get_data(as_text=True)
        assert client.get('/feeds').status_code in (302, 401)

    def test_analyze_precarga_desde_la_query(self, analyst_client):
        html = analyst_client.get('/analyze?ioc=CVE-2021-44228&type=cve').get_data(as_text=True)
        assert 'prefillFromQuery' in html and "new URLSearchParams(location.search)" in html

    def test_las_rutas_a_las_que_llama_la_pagina_existen(self, app):
        reglas = {(r.rule.replace('<int:entry_id>', '{id}'), m) for r in app.url_map.iter_rules() for m in r.methods}
        for ruta, metodo in [('/api/v2/feeds/status', 'GET'), ('/api/v2/feeds/items', 'GET'), ('/api/v2/feeds/stack', 'GET'),
                             ('/api/v2/feeds/stack', 'POST'), ('/api/v2/feeds/stack/{id}', 'DELETE')]:
            assert (ruta, metodo) in reglas, (ruta, metodo)


# ============================================================================ CLI

class TestCli:
    def test_stack_run_status(self, app, db_session):
        runner = app.test_cli_runner()
        assert 'añadida' in runner.invoke(args=['feeds', 'stack-add', '--vendor', 'Cisco']).output
        assert 'Cisco' in runner.invoke(args=['feeds', 'stack-list']).output
        with patch.object(feed_sources, 'fetch_kev', return_value=[_item('CVE-2026-1', source='cisa_kev', in_kev=True,
                                                                          kev_date_added=date(2026, 11, 19))]), \
                patch.object(feed_sources, 'fetch_nvd_recent', return_value=[_item('CVE-2026-2')]), \
                patch.object(feed_sources, 'fetch_epss', return_value={}):
            out = runner.invoke(args=['feeds', 'run']).output
        assert 'cisa_kev' in out and 'nvd_recent' in out and 'alertas=1' in out
        st = runner.invoke(args=['feeds', 'status']).output
        assert 'CVEs: 2 total, 2 relevantes' in st and 'vencida=no' in st

    def test_run_muestra_el_error(self, app, db_session):
        with patch.object(feed_sources, 'fetch_kev', side_effect=FeedError('KEV: HTTP 503')), \
                patch.object(feed_sources, 'fetch_nvd_recent', return_value=[]), patch.object(feed_sources, 'fetch_epss', return_value={}):
            out = app.test_cli_runner().invoke(args=['feeds', 'run']).output
        assert 'ERROR: KEV: HTTP 503' in out

    def test_stack_add_rechaza_entradas_vacias(self, app, db_session):
        r = app.test_cli_runner().invoke(args=['feeds', 'stack-add', '--vendor', 'Inc'])
        assert r.exit_code != 0 and TechStackEntry.query.count() == 0

    def test_stack_remove(self, app, db_session):
        e = _stack(db_session, ('Cisco', None))[0]
        assert 'borrada' in app.test_cli_runner().invoke(args=['feeds', 'stack-remove', str(e.id)]).output
        assert app.test_cli_runner().invoke(args=['feeds', 'stack-remove', '999999']).exit_code != 0


# ============================================================================ DESPLIEGUE

class TestDespliegue:
    def _compose(self):
        import yaml
        return yaml.safe_load((ROOT / 'docker-compose.yml').read_text(encoding='utf-8'))

    def test_servicio_feeds_en_compose(self):
        svc = self._compose()['services']
        feeds = svc['feeds']
        assert feeds['command'] == ['flask', 'feeds', 'daemon']
        assert feeds['image'] == svc['app']['image'] == 'soc-agent:latest'           # una sola construcción
        assert feeds['depends_on']['app']['condition'] == 'service_healthy'         # la app aplica las migraciones
        assert 'FLASK_APP=wsgi.py' in feeds['environment']                           # .env.docker no tiene por qué traerlo
        assert 'ports' not in feeds and feeds['restart'] == 'unless-stopped'

    def test_el_planificador_no_esta_en_el_proceso_web(self):
        """Gunicorn arranca 3 workers: un planificador dentro de la app se ejecutaría 3 veces."""
        wsgi = (ROOT / 'wsgi.py').read_text(encoding='utf-8')
        init = (ROOT / 'app' / '__init__.py').read_text(encoding='utf-8')
        for texto in (wsgi, init):
            assert 'feed_runner' not in texto and 'APScheduler' not in texto and 'daemon(' not in texto

    def test_verify_docker_comprueba_el_servicio_feeds(self):
        sh = (ROOT / 'scripts' / 'ops' / 'verify_docker.sh').read_text(encoding='utf-8')
        assert 'feeds daemon iniciado' in sh and 'feeds sin reinicios' in sh and 'cisa_kev .*última=ok' in sh
        assert 'feeds:' in sh and '\r\n' not in sh


# ============================================================================ REPASO (auditoría 2026-11-19)

class TestEsperaTrasUnFallo:
    """R2: sin espera, con NVD caído el daemon reintentaba cada 5 min indefinidamente y escribía una fila en feed_runs cada vez."""

    def _fallo(self, db_session):
        boom = lambda s, n: (_ for _ in ()).throw(FeedError('NVD HTTP 429'))
        feed_runner.run_source('nvd_recent', now=NOW, fetchers={'nvd_recent': boom}, enrich_epss=False)

    def test_no_reintenta_dentro_de_la_espera(self, app, db_session):
        self._fallo(db_session)
        assert not feed_runner.is_due('nvd_recent', NOW)
        assert not feed_runner.is_due('nvd_recent', NOW + feed_runner.ERROR_BACKOFF - timedelta(minutes=1))
        assert feed_runner.is_due('nvd_recent', NOW + feed_runner.ERROR_BACKOFF)

    def test_control_sin_fallos_previos_esta_vencida_al_instante(self, app, db_session):
        assert feed_runner.is_due('nvd_recent', NOW)

    def test_la_espera_es_por_fuente(self, app, db_session):
        self._fallo(db_session)
        assert feed_runner.is_due('cisa_kev', NOW)

    def test_un_exito_posterior_cancela_la_espera(self, app, db_session):
        self._fallo(db_session)
        later = NOW + feed_runner.ERROR_BACKOFF
        feed_runner.run_source('nvd_recent', now=later, fetchers={'nvd_recent': lambda s, n: []}, enrich_epss=False)
        assert not feed_runner.is_due('nvd_recent', later + timedelta(hours=1))
        assert feed_runner.is_due('nvd_recent', later + feed_runner.SOURCES['nvd_recent'].interval)

    def test_el_daemon_no_martilla_la_fuente(self, app, db_session):
        """4 ciclos de 5 min con la fuente caída = 1 ejecución, no 4."""
        calls = []

        def boom(since, now):
            calls.append(now)
            raise FeedError('caído')

        for minutos in (0, 5, 10, 15):
            if feed_runner.is_due('nvd_recent', NOW + timedelta(minutes=minutos)):
                feed_runner.run_source('nvd_recent', now=NOW + timedelta(minutes=minutos),
                                       fetchers={'nvd_recent': boom}, enrich_epss=False)
        assert len(calls) == 1 and FeedRun.query.filter_by(source='nvd_recent').count() == 1


class TestEjecucionesColgadas:
    """F6/R8: un kill -9 a mitad de ejecución dejaba un 'running' eterno."""

    def test_se_marcan_como_error_al_siguiente_run(self, app, db_session):
        fantasma = FeedRun(source='nvd_recent', started_at=NOW - timedelta(hours=2), status='running')
        otra = FeedRun(source='cisa_kev', started_at=NOW - timedelta(hours=2), status='running')
        db_session.session.add_all([fantasma, otra])
        db_session.session.commit()
        feed_runner.run_source('nvd_recent', now=NOW, fetchers={'nvd_recent': lambda s, n: []}, enrich_epss=False)
        db_session.session.refresh(fantasma)
        db_session.session.refresh(otra)
        assert fantasma.status == 'error' and 'interrumpida' in fantasma.error and fantasma.finished_at
        assert otra.status == 'running'                          # control: no toca otras fuentes

    def test_no_se_toca_la_ejecucion_de_otra_instancia_que_tiene_el_lock(self, app, db_session):
        """Si el lock lo tiene otra instancia, run_source sale ANTES de limpiar: su 'running' es legítimo."""
        viva = FeedRun(source='nvd_recent', started_at=NOW, status='running')
        db_session.session.add(viva)
        db_session.session.commit()
        other = db.engine.connect()
        try:
            other.execute(text('SELECT pg_try_advisory_lock(:k)'), {'k': feed_runner._lock_key('nvd_recent')})
            assert feed_runner.run_source('nvd_recent', now=NOW, fetchers={}, enrich_epss=False)['status'] == 'skipped'
            db_session.session.refresh(viva)
            assert viva.status == 'running'
        finally:
            other.execute(text('SELECT pg_advisory_unlock(:k)'), {'k': feed_runner._lock_key('nvd_recent')})
            other.close()


class TestLockSinTransaccionAbierta:
    """F5: la conexión del lock no debe quedar 'idle in transaction' durante el fetch HTTP."""

    def test_durante_la_ejecucion_no_hay_transaccion_ociosa_del_lock(self, app, db_session):
        visto = {}

        def fetcher(since, now):
            visto['n'] = db.session.execute(text(
                "select count(*) from pg_stat_activity where datname = current_database() "
                "and state like 'idle in transaction%' and query ilike '%pg_try_advisory_lock%'")).scalar()
            return []

        feed_runner.run_source('nvd_recent', now=NOW, fetchers={'nvd_recent': fetcher}, enrich_epss=False)
        assert visto['n'] == 0

    def test_el_lock_se_mantiene_durante_la_ejecucion(self, app, db_session):
        """Control: AUTOCOMMIT no debe haber roto el lock: mientras corre, otra conexión NO puede tomarlo."""
        visto = {}

        def fetcher(since, now):
            c = db.engine.connect()
            try:
                visto['otro_puede'] = c.execute(text('SELECT pg_try_advisory_lock(:k)'),
                                                {'k': feed_runner._lock_key('nvd_recent')}).scalar()
            finally:
                c.close()
            return []

        feed_runner.run_source('nvd_recent', now=NOW, fetchers={'nvd_recent': fetcher}, enrich_epss=False)
        assert visto['otro_puede'] is False


class TestReconciliacionDeRelevancia:
    """F4: el runner lee el stack al empezar el upsert; si cambia mientras tanto, su commit dejaba la relevancia vieja."""

    def test_un_cambio_de_stack_durante_el_upsert_no_se_pierde(self, app, db_session):
        original = feed_runner.upsert_item
        hecho = {'n': 0}

        def upsert_y_cambia_el_stack(data, entries, now):
            r = original(data, entries, now)
            if not hecho['n']:                                   # otra sesión añade la entrada a mitad de la ejecución
                hecho['n'] = 1
                db.session.add(TechStackEntry(vendor='Cisco'))
                db.session.commit()
            return r

        with patch.object(feed_runner, 'upsert_item', side_effect=upsert_y_cambia_el_stack):
            feed_runner.run_source('nvd_recent', now=NOW, fetchers={'nvd_recent': lambda s, n: [_item()]}, enrich_epss=False)
        assert FeedItem.query.one().is_relevant is True

    def test_si_la_reconciliacion_falla_el_run_sigue_siendo_ok(self, app, db_session):
        with patch.object(feed_runner, 'recompute_relevance', side_effect=RuntimeError('boom')):
            r = feed_runner.run_source('nvd_recent', now=NOW, fetchers={'nvd_recent': lambda s, n: [_item()]}, enrich_epss=False)
        assert r['status'] == 'ok' and FeedItem.query.count() == 1 and FeedRun.query.one().status == 'ok'


class TestStackSiRecalcularFalla:
    """F7: la entrada ya está guardada; un 500 haría reintentar al cliente y chocar con el duplicado."""

    def test_alta_responde_201_y_la_entrada_queda(self, app, db_session, senior):
        with patch.object(feed_runner, 'recompute_relevance', side_effect=RuntimeError('boom')):
            r = senior.post(f'{BASE}/stack', json={'vendor': 'Cisco'})
        assert r.status_code == 201 and r.get_json()['relevance'] is None and TechStackEntry.query.count() == 1

    def test_baja_responde_200(self, app, db_session, senior):
        e = _stack(db_session, ('Cisco', None))[0]
        with patch.object(feed_runner, 'recompute_relevance', side_effect=RuntimeError('boom')):
            r = senior.delete(f'{BASE}/stack/{e.id}')
        assert r.status_code == 200 and TechStackEntry.query.count() == 0
