"""
Avisos de los feeds por Telegram (WP7 de PLAN-FUSION, v1: salientes).

Formas de respuesta: el 401 es el REAL de la API de Telegram (capturado el 2026-11-20 con un token inválido); los textos de excepción
con el token son los REALES de `requests` (ConnectionError y HTTPError). 200/400/403/429 siguen la documentación de la API de bots.

La propiedad de seguridad central: el token NO aparece nunca (ni en un mensaje de error, ni en un log, ni en una respuesta, ni en la
auditoría, ni en feed_runs), ni siquiera ante los fallos que lo incluyen en el texto de la excepción.
"""
import importlib
import logging
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import requests

from app import db
from app.models.audit import AuditEvent
from app.models.feed import FeedItem, FeedRun, TechStackEntry
from app.services import feed_notifier, feed_runner, telegram_client as tg
from app.services.telegram_client import TelegramError, escape, mask_chat, redact, split_message
from app.utils.time_utils import utcnow

TOKEN = '123456789:AAFAKE_tokenSecretoQueNoDebeFiltrarse_xyz'
CHATS = (1111111, -1002222222)


def _resp(status=200, payload=None, json_error=False):
    m = MagicMock()
    m.status_code = status
    if json_error:
        m.json.side_effect = ValueError('no json')
    else:
        m.json.return_value = payload
    return m


OK = _resp(200, {'ok': True, 'result': {'message_id': 7, 'chat': {'id': 1111111}, 'date': 1, 'text': 'x'}})
R401 = (401, {'ok': False, 'error_code': 401, 'description': 'Unauthorized'})                                # REAL
R400 = (400, {'ok': False, 'error_code': 400, 'description': 'Bad Request: chat not found'})
R403 = (403, {'ok': False, 'error_code': 403, 'description': 'Forbidden: bot was blocked by the user'})
R429 = (429, {'ok': False, 'error_code': 429, 'description': 'Too Many Requests: retry after 5', 'parameters': {'retry_after': 5}})
# textos de excepcion REALES de requests (con el token dentro de la URL)
EX_CONN = requests.exceptions.ConnectionError(
    f"HTTPSConnectionPool(host='api.telegram.org', port=443): Max retries exceeded with url: /bot{TOKEN}/sendMessage "
    f"(Caused by NameResolutionError(\"HTTPSConnection(host='api.telegram.org', port=443): Failed to resolve\"))")
EX_HTTP = requests.exceptions.HTTPError(f'401 Client Error: Unauthorized for url: https://api.telegram.org/bot{TOKEN}/sendMessage')


@pytest.fixture
def tgcfg(app):
    """Configura Telegram (token + 2 chats) y lo restaura."""
    antes = {k: app.config.get(k) for k in ('TELEGRAM_BOT_TOKEN', 'TELEGRAM_ALERT_CHAT_IDS', 'TELEGRAM_MIN_RISK',
                                              'TELEGRAM_BACKLOG_DAYS', 'APP_BASE_URL')}
    app.config.update(TELEGRAM_BOT_TOKEN=TOKEN, TELEGRAM_ALERT_CHAT_IDS=CHATS, TELEGRAM_MIN_RISK='ALTO',
                      TELEGRAM_BACKLOG_DAYS=3, APP_BASE_URL='https://soc.example.org')
    feed_notifier.reset_backoff()
    yield app
    app.config.update(antes)
    feed_notifier.reset_backoff()


@pytest.fixture
def app_ctx(app):
    with app.app_context():
        yield


def _http(*respuestas):
    """Parche de http_post con respuestas en orden (o excepciones)."""
    seq = [r if isinstance(r, (MagicMock, BaseException)) else _resp(*r) for r in respuestas]
    return patch.object(tg, 'http_post', side_effect=seq)


def _item(db_session, cve='CVE-2026-1', riesgo='ALTO', score=60, relevant=True, notified=None, dias=0, kev=False, **kw):
    it = FeedItem(cve_id=cve, title=kw.pop('title', f'Titulo de {cve}'), risk_level=riesgo, priority_score=score, is_relevant=relevant,
                  notified_at=notified, in_kev=kev, affected=[{'vendor': 'Cisco', 'product': 'IOS XE'}], matched_entries=[],
                  sources=['nvd_recent'], **kw)
    db_session.session.add(it)
    db_session.session.commit()
    if dias:
        FeedItem.query.filter_by(cve_id=cve).update({'updated_at': utcnow() - timedelta(days=dias)})
        db_session.session.commit()
    return it


# ============================================================================ REDACTADO

class TestRedact:
    @pytest.mark.parametrize('texto', [
        f'401 Client Error: Unauthorized for url: https://api.telegram.org/bot{TOKEN}/sendMessage',
        f"Max retries exceeded with url: /bot{TOKEN}/sendMessage", f'token={TOKEN}', f'{TOKEN}', f'a {TOKEN} b {TOKEN} c',
    ])
    def test_quita_el_token_explicito(self, texto):
        assert TOKEN not in redact(texto, TOKEN)

    def test_quita_el_configurado_sin_pasarlo(self, tgcfg, app_ctx):
        assert TOKEN not in redact(f'url /bot{TOKEN}/x')

    def test_quita_cualquier_token_con_la_forma_del_de_telegram_aunque_no_sea_el_configurado(self):
        otro = '987654321:AAGotroTokenDistintoDeLargoSuficiente_01'
        out = redact(f'fallo en /bot{otro}/getMe y suelto {otro}')
        assert otro not in out and '<TOKEN>' in out

    def test_control_no_destruye_texto_normal(self):
        txt = 'Telegram respondió 401: Unauthorized (CVE-2026-1, host 10:30:45)'
        assert redact(txt) == txt

    @pytest.mark.parametrize('valor', [None, 0, ['a'], ValueError('x')])
    def test_acepta_cualquier_tipo(self, valor):
        assert isinstance(redact(valor, TOKEN), str)

    def test_mask_chat(self):
        assert mask_chat(1111111) == '…111' and mask_chat(-1002222222) == '…222' and mask_chat(5) == '…'


# ============================================================================ CLIENTE

class TestCliente:
    def test_exito(self, tgcfg, app_ctx):
        with _http(OK) as h:
            assert tg.send_message(1111111, '<b>hola</b>') == 1
        payload = h.call_args.kwargs['json']
        assert payload['chat_id'] == 1111111 and payload['parse_mode'] == 'HTML' and payload['disable_web_page_preview'] is True
        assert h.call_args.args[0].startswith('https://api.telegram.org/bot')

    def test_401_real_es_permanente_y_no_filtra(self, tgcfg, app_ctx):
        with _http(R401), pytest.raises(TelegramError) as e:
            tg.send_message(1, 'x')
        assert e.value.permanent and e.value.code == 401 and TOKEN not in str(e.value)

    @pytest.mark.parametrize('resp,permanente', [(R400, True), (R403, True), (R401, True), (R429, False), ((500, {}), False),
                                                  ((502, {'ok': False}), False)])
    def test_clasificacion_permanente_o_transitoria(self, tgcfg, app_ctx, resp, permanente):
        with _http(resp), pytest.raises(TelegramError) as e:
            tg.send_message(1, 'x')
        assert e.value.permanent is permanente

    def test_si_la_descripcion_de_telegram_repitiera_el_token_tampoco_se_filtra(self, tgcfg, app_ctx):
        """Defensa en profundidad: NINGÚN texto que salga de este módulo puede llevar el token, venga de donde venga."""
        eco = (400, {'ok': False, 'error_code': 400, 'description': f'Bad Request: bad url /bot{TOKEN}/sendMessage'})
        with _http(eco), pytest.raises(TelegramError) as e:
            tg.send_message(1, 'x')
        assert TOKEN not in str(e.value) and '<TOKEN>' in str(e.value)

    def test_429_trae_retry_after(self, tgcfg, app_ctx):
        with _http(R429), pytest.raises(TelegramError) as e:
            tg.send_message(1, 'x')
        assert e.value.retry_after == 5 and not e.value.permanent

    def test_cuerpo_no_json(self, tgcfg, app_ctx):
        with _http(_resp(200, json_error=True)), pytest.raises(TelegramError):
            tg.send_message(1, 'x')

    def test_200_con_ok_false_es_error(self, tgcfg, app_ctx):
        with _http((200, {'ok': False, 'error_code': 400, 'description': 'Bad Request'})), pytest.raises(TelegramError):
            tg.send_message(1, 'x')

    @pytest.mark.parametrize('exc', [EX_CONN, EX_HTTP, requests.exceptions.Timeout(f'timeout en /bot{TOKEN}/sendMessage'), OSError(TOKEN)])
    def test_una_excepcion_de_red_que_contiene_el_token_no_lo_filtra(self, tgcfg, app_ctx, exc):
        assert TOKEN in str(exc)                                  # control: el texto ORIGINAL sí lo lleva
        with _http(exc), pytest.raises(TelegramError) as e:
            tg.send_message(1, 'x')
        assert TOKEN not in str(e.value) and not e.value.permanent
        assert e.value.__cause__ is None                          # `from None`: la cadena original no viaja en el traceback

    def test_sin_token_falla_permanente_sin_llamar(self, app, app_ctx):
        app.config['TELEGRAM_BOT_TOKEN'] = None
        with patch.object(tg, 'http_post') as h, pytest.raises(TelegramError) as e:
            tg.send_message(1, 'x')
        assert e.value.permanent and not h.called

    def test_trocea_en_varios_envios(self, tgcfg, app_ctx):
        with _http(*[OK] * 12) as h:
            n = tg.send_message(1, '\n'.join(['linea ' + 'x' * 100] * 200))
        assert n == h.call_count and n > 1

    def test_un_trozo_que_falla_corta_el_envio(self, tgcfg, app_ctx):
        with _http(OK, R429), pytest.raises(TelegramError):
            tg.send_message(1, '\n'.join(['linea ' + 'x' * 100] * 200))

    def test_get_me(self, tgcfg, app_ctx):
        with _http(_resp(200, {'ok': True, 'result': {'id': 1, 'is_bot': True, 'username': 'soc_bot'}})):
            assert tg.get_me()['username'] == 'soc_bot'


class TestTroceoYEscape:
    def test_no_pierde_nada_y_respeta_el_limite(self):
        texto = '\n'.join(f'<b>L{i}</b> ' + 'y' * 90 for i in range(300))
        partes = split_message(texto)
        assert all(len(p) <= tg.MAX_CHARS for p in partes) and '\n'.join(partes) == texto and len(partes) > 1

    def test_cada_trozo_tiene_las_etiquetas_completas(self):
        partes = split_message('\n'.join(f'<b>L{i}</b> ' + 'y' * 90 for i in range(300)))
        assert all(p.count('<b>') == p.count('</b>') for p in partes)

    def test_una_linea_gigante(self):
        partes = split_message('z' * 9000)
        assert [len(p) for p in partes] == [4000, 4000, 1000]

    def test_texto_corto_un_solo_trozo(self):
        assert split_message('hola') == ['hola'] and split_message('') == ['']

    def test_escape_de_html_no_confiable(self):
        assert escape('<script>alert(1)</script> & <a href="x">') == '&lt;script&gt;alert(1)&lt;/script&gt; &amp; &lt;a href="x"&gt;'


class TestEnvioAChatsPermitidos:
    def test_solo_a_la_lista_permitida(self, tgcfg, app_ctx):
        with _http(OK, OK) as h:
            r = tg.send_to_chats('hola', chat_ids=[1111111, 999999999, -1002222222])
        assert r['sent'] == [1111111, -1002222222] and h.call_count == 2       # el 999999999 NO está permitido: nunca se llama

    def test_por_defecto_envia_a_todos_los_permitidos(self, tgcfg, app_ctx):
        with _http(OK, OK):
            assert tg.send_to_chats('hola')['sent'] == list(CHATS)

    def test_clasifica_los_errores_por_chat_y_los_redacta(self, tgcfg, app_ctx):
        with _http(EX_CONN, R403):
            r = tg.send_to_chats('hola')
        assert [c for c, _ in r['transient']] == [1111111] and [c for c, _ in r['permanent']] == [-1002222222]
        assert TOKEN not in str(r)

    def test_configured_exige_token_y_chats(self, app, app_ctx):
        app.config.update(TELEGRAM_BOT_TOKEN=None, TELEGRAM_ALERT_CHAT_IDS=())
        assert not tg.configured()
        app.config['TELEGRAM_BOT_TOKEN'] = TOKEN
        assert not tg.configured()
        app.config['TELEGRAM_ALERT_CHAT_IDS'] = (1,)
        assert tg.configured()
        app.config['TELEGRAM_BOT_TOKEN'] = None
        assert not tg.configured()


# ============================================================================ SELECCIÓN DE LO PENDIENTE

class TestPendientes:
    def test_solo_relevantes_no_avisados_y_sobre_el_umbral(self, tgcfg, db_session):
        _item(db_session, 'CVE-2026-1', 'ALTO', 60)
        _item(db_session, 'CVE-2026-2', 'CRÍTICO', 90)
        _item(db_session, 'CVE-2026-3', 'MEDIO', 35)                           # bajo el umbral
        _item(db_session, 'CVE-2026-4', 'ALTO', 55, relevant=False)           # no afecta al stack
        _item(db_session, 'CVE-2026-5', 'ALTO', 55, notified=utcnow())        # ya avisado
        assert [i.cve_id for i in feed_notifier.pending_items()] == ['CVE-2026-2', 'CVE-2026-1']      # por prioridad

    def test_umbral_configurable(self, tgcfg, db_session):
        _item(db_session, 'CVE-2026-1', 'MEDIO', 35)
        assert feed_notifier.pending_items() == []
        tgcfg.config['TELEGRAM_MIN_RISK'] = 'MEDIO'
        assert len(feed_notifier.pending_items()) == 1

    @pytest.mark.parametrize('valor,esperado', [('critico', 'CRÍTICO'), ('CRITICO', 'CRÍTICO'), ('alto', 'ALTO'), ('basura', 'ALTO'), ('', 'ALTO')])
    def test_umbral_normalizado_y_con_respaldo(self, tgcfg, valor, esperado):
        tgcfg.config['TELEGRAM_MIN_RISK'] = valor
        with tgcfg.app_context():
            assert feed_notifier.min_risk() == esperado

    def test_al_activarlo_no_inunda_con_el_historico(self, tgcfg, db_session):
        _item(db_session, 'CVE-2026-1', 'ALTO', 60, dias=10)                   # antiguo: fuera de la ventana de 3 días
        _item(db_session, 'CVE-2026-2', 'ALTO', 60, dias=1)
        assert [i.cve_id for i in feed_notifier.pending_items()] == ['CVE-2026-2']

    def test_un_kev_entra_con_el_umbral_alto_por_su_suelo(self, tgcfg, db_session):
        feed_runner.upsert_item({'cve_id': 'CVE-2026-9', 'title': 't', 'summary': '', 'published_at': utcnow(), 'source': 'cisa_kev',
                                 'affected': [{'vendor': 'Cisco', 'product': 'IOS XE'}], 'in_kev': True, 'kev_date_added': utcnow().date(),
                                 'known_ransomware': False, 'cvss_score': None, 'epss': None},
                                [SimpleNamespace(id=1, vendor='Cisco', product=None)], utcnow())
        db_session.session.commit()
        assert [i.cve_id for i in feed_notifier.pending_items()] == ['CVE-2026-9']

    def test_escalar_a_kev_vuelve_a_dejar_pendiente_uno_ya_avisado(self, tgcfg, db_session):
        entradas = [SimpleNamespace(id=1, vendor='Cisco', product=None)]
        base = {'cve_id': 'CVE-2026-7', 'title': 't', 'summary': '', 'published_at': utcnow(), 'source': 'nvd_recent',
                'affected': [{'vendor': 'Cisco', 'product': 'IOS XE'}], 'in_kev': False, 'kev_date_added': None,
                'known_ransomware': False, 'cvss_score': 9.8, 'epss': 0.6}
        feed_runner.upsert_item(base, entradas, utcnow())
        db_session.session.commit()
        FeedItem.query.one().notified_at = utcnow()
        db_session.session.commit()
        assert feed_notifier.pending_items() == []
        feed_runner.upsert_item({**base, 'source': 'cisa_kev', 'in_kev': True, 'kev_date_added': utcnow().date()}, entradas, utcnow())
        db_session.session.commit()
        assert [i.cve_id for i in feed_notifier.pending_items()] == ['CVE-2026-7']


# ============================================================================ MENSAJE

class TestMensaje:
    def test_contenido_y_enlace(self, tgcfg, db_session):
        it = _item(db_session, 'CVE-2026-1', 'ALTO', 60, kev=True, known_ransomware=True, cvss_score=9.8, epss=0.62)
        txt = feed_notifier.format_message([it], 1, 'https://soc.example.org', {})
        assert '<b>SOC Agent: 1 CVE afecta a tu stack</b>' in txt and '<b>CVE-2026-1</b>' in txt and 'KEV · ransomware' in txt
        assert 'CVSS 9.8' in txt and 'EPSS 62%' in txt and 'Cisco IOS XE' in txt
        assert '<a href="https://soc.example.org/analyze?ioc=CVE-2026-1&amp;type=cve">Analizar</a>' in txt

    def test_sin_base_url_no_hay_enlace(self, tgcfg, db_session):
        it = _item(db_session)
        assert '<a ' not in feed_notifier.format_message([it], 1, '', {})

    def test_el_texto_no_confiable_se_escapa(self, tgcfg, db_session):
        it = _item(db_session, title='<script>alert(1)</script> & "x" <a href="http://evil">clic</a>')
        txt = feed_notifier.format_message([it], 1, '', {})
        assert '<script>' not in txt and '&lt;script&gt;' in txt and '<a href="http://evil">' not in txt

    def test_plural_y_resto(self, tgcfg, db_session):
        its = [_item(db_session, f'CVE-2026-{i}') for i in range(1, 4)]
        txt = feed_notifier.format_message(its[:2], 3, 'https://soc.example.org', {})
        assert '3 CVE afectan a tu stack' in txt and '…y 1 más en https://soc.example.org/feeds' in txt

    def test_titulo_largo_se_recorta(self, tgcfg, db_session):
        assert 'x' * 200 not in feed_notifier.format_message([_item(db_session, title='x' * 300)], 1, '', {})

    def test_usa_las_etiquetas_del_stack(self, tgcfg, db_session):
        it = _item(db_session)
        it.matched_entries = [5]
        assert 'Afecta a: Fortinet FortiOS' in feed_notifier.format_message([it], 1, '', {5: 'Fortinet FortiOS'})

    def test_cabe_en_telegram(self, tgcfg, db_session):
        its = [_item(db_session, f'CVE-2026-{i}', title='t' * 300) for i in range(1, 11)]
        assert len(feed_notifier.format_message(its, 10, 'https://soc.example.org', {})) < 4096 * 2


# ============================================================================ NOTIFICAR

class TestNotificar:
    def test_sin_configurar_no_hace_nada_ni_llama_a_la_red(self, app, db_session):
        app.config.update(TELEGRAM_BOT_TOKEN=None, TELEGRAM_ALERT_CHAT_IDS=())
        _item(db_session)
        with patch.object(tg, 'http_post') as h:
            assert feed_notifier.notify_pending() == {'status': 'disabled', 'items': 0}
        assert not h.called and FeedItem.query.one().notified_at is None

    def test_nada_pendiente(self, tgcfg, db_session):
        with patch.object(tg, 'http_post') as h:
            assert feed_notifier.notify_pending()['status'] == 'idle'
        assert not h.called

    def test_enviado_marca_solo_lo_mostrado_y_audita(self, tgcfg, db_session):
        for i in range(1, 13):
            _item(db_session, f'CVE-2026-{i}', 'ALTO', 100 - i)
        with _http(OK, OK) as h:
            r = feed_notifier.notify_pending()
        assert r['status'] == 'sent' and r['items'] == 10 and r['pendientes'] == 12 and r['recibieron'] == 2
        assert FeedItem.query.filter(FeedItem.notified_at.isnot(None)).count() == 10
        assert [i.cve_id for i in feed_notifier.pending_items()] == ['CVE-2026-11', 'CVE-2026-12']      # el resto sigue pendiente
        ev = AuditEvent.query.filter_by(action='telegram_alert_sent').one()
        assert ev.details['chats'] == ['…111', '…222'] and len(ev.details['cves']) == 10 and TOKEN not in str(ev.details)
        assert h.call_count == 2                                            # un mensaje por chat, agrupado

    def test_un_solo_mensaje_por_chat_aunque_haya_varios_cve(self, tgcfg, db_session):
        for i in range(1, 6):
            _item(db_session, f'CVE-2026-{i}')
        with _http(OK, OK) as h:
            feed_notifier.notify_pending()
        assert h.call_count == 2

    def test_fallo_transitorio_no_marca_y_se_reintenta(self, tgcfg, db_session):
        _item(db_session)
        with _http(EX_CONN, EX_CONN):
            r = feed_notifier.notify_pending()
        assert r['status'] == 'retry' and FeedItem.query.one().notified_at is None
        assert AuditEvent.query.filter_by(action='telegram_alert_sent').count() == 0
        with _http(OK, OK):
            assert feed_notifier.notify_pending()['status'] == 'sent'
        assert FeedItem.query.one().notified_at is not None                 # nada se perdió

    def test_un_transitorio_en_un_chat_bloquea_el_marcado_aunque_el_otro_lo_recibiera(self, tgcfg, db_session):
        """Se prefiere un duplicado a perder una alerta."""
        _item(db_session)
        with _http(OK, R429):
            r = feed_notifier.notify_pending()
        assert r['status'] == 'retry' and r['recibieron'] == 1 and FeedItem.query.one().notified_at is None

    def test_un_permanente_en_un_chat_no_bloquea_al_resto(self, tgcfg, db_session):
        """Bot bloqueado en un chat: reintentar no lo arregla y repetiría el aviso al otro en cada ciclo."""
        _item(db_session)
        with _http(OK, R403):
            r = feed_notifier.notify_pending()
        assert r['status'] == 'sent' and r['permanentes'] == 1 and FeedItem.query.one().notified_at is not None

    def test_si_nadie_lo_recibe_no_se_marca_nada(self, tgcfg, db_session):
        _item(db_session)
        with _http(R401, R401):
            r = feed_notifier.notify_pending()
        assert r['status'] == 'undeliverable' and FeedItem.query.one().notified_at is None

    def test_una_excepcion_inesperada_no_rompe_y_no_filtra(self, tgcfg, db_session):
        _item(db_session)
        with patch.object(feed_notifier.telegram_client, 'send_to_chats', side_effect=RuntimeError(f'boom {TOKEN}')):
            r = feed_notifier.notify_pending()
        assert r['status'] == 'retry' and TOKEN not in str(r) and FeedItem.query.one().notified_at is None

    def test_el_audit_event_se_guarda_con_el_marcado_en_una_transaccion(self, tgcfg, db_session):
        _item(db_session)
        with _http(OK, OK):
            feed_notifier.notify_pending()
        db_session.session.expire_all()
        assert AuditEvent.query.filter_by(action='telegram_alert_sent').count() == 1


class TestEsperaTrasUnFallo:
    def test_no_reintenta_dentro_de_la_espera(self, tgcfg, db_session):
        _item(db_session)
        ahora = utcnow()
        with _http(EX_CONN, EX_CONN) as h:
            assert feed_notifier.maybe_notify(ahora)['status'] == 'retry'
        n = h.call_count
        with patch.object(tg, 'http_post') as h2:
            assert feed_notifier.maybe_notify(ahora + timedelta(minutes=5))['status'] == 'backoff'
        assert not h2.called and n == 2

    def test_pasada_la_espera_reintenta_y_se_recupera(self, tgcfg, db_session):
        _item(db_session)
        ahora = utcnow()
        with _http(EX_CONN, EX_CONN):
            feed_notifier.maybe_notify(ahora)
        with _http(OK, OK):
            assert feed_notifier.maybe_notify(ahora + feed_notifier.RETRY_BACKOFF)['status'] == 'sent'
        assert feed_notifier.maybe_notify(ahora + timedelta(hours=1))['status'] == 'idle'        # la espera se canceló

    def test_control_sin_fallos_no_hay_espera(self, tgcfg, db_session):
        _item(db_session, 'CVE-2026-1')
        with _http(OK, OK):
            feed_notifier.maybe_notify()
        _item(db_session, 'CVE-2026-2')
        with _http(OK, OK):
            assert feed_notifier.maybe_notify()['status'] == 'sent'


class TestDaemon:
    def test_el_daemon_avisa_en_cada_ciclo(self, tgcfg, db_session):
        ciclos = {'n': 0}
        with patch.object(feed_runner, 'run_due', return_value=[]), \
                patch.object(feed_notifier, 'maybe_notify', return_value={'status': 'sent', 'items': 1}) as mn:
            feed_runner.daemon(poll_seconds=1, stop=lambda: ciclos['n'] >= 3, sleep=lambda s: ciclos.__setitem__('n', ciclos['n'] + 1))
        assert mn.call_count == 3

    def test_un_fallo_al_avisar_no_mata_el_daemon(self, tgcfg, db_session):
        ciclos = {'n': 0}
        with patch.object(feed_runner, 'run_due', return_value=[]), \
                patch.object(feed_notifier, 'maybe_notify', side_effect=[RuntimeError('boom'), {'status': 'idle', 'items': 0}]) as mn:
            feed_runner.daemon(poll_seconds=1, stop=lambda: ciclos['n'] >= 2, sleep=lambda s: ciclos.__setitem__('n', ciclos['n'] + 1))
        assert mn.call_count == 2

    def test_sin_telegram_el_daemon_se_comporta_como_antes(self, app, db_session):
        app.config.update(TELEGRAM_BOT_TOKEN=None, TELEGRAM_ALERT_CHAT_IDS=())
        ciclos = {'n': 0}
        with patch.object(feed_runner, 'run_due', return_value=[]), patch.object(tg, 'http_post') as h:
            feed_runner.daemon(poll_seconds=1, stop=lambda: ciclos['n'] >= 2, sleep=lambda s: ciclos.__setitem__('n', ciclos['n'] + 1))
        assert not h.called


# ============================================================================ EL TOKEN NO SE FILTRA (propiedad central)

FALLOS = [EX_CONN, EX_HTTP, R401, R403, R429, (500, {}), _resp(200, json_error=True)]


class TestElTokenNoSeFiltraNunca:
    @pytest.mark.parametrize('fallo', FALLOS, ids=lambda f: type(f).__name__ if isinstance(f, BaseException) else str(f)[:24])
    def test_en_ningun_sitio(self, tgcfg, db_session, caplog, fallo):
        _item(db_session)
        caplog.set_level(logging.DEBUG)
        with _http(fallo, fallo):
            resultado = feed_notifier.notify_pending()
        db_session.session.expire_all()
        todo = ' | '.join([
            str(resultado), caplog.text,
            ' '.join(str(e.details) + str(e.username) for e in AuditEvent.query.all()),
            ' '.join(str(r.error) for r in FeedRun.query.all()),
        ])
        assert TOKEN not in todo, 'el token apareció en: ' + todo[:300]

    def test_ni_en_el_exito(self, tgcfg, db_session, caplog):
        _item(db_session)
        caplog.set_level(logging.DEBUG)
        with _http(OK, OK):
            r = feed_notifier.notify_pending()
        assert TOKEN not in str(r) + caplog.text + str([e.details for e in AuditEvent.query.all()])

    def test_ni_la_salida_de_la_linea_de_comandos(self, tgcfg, db_session):
        runner = tgcfg.test_cli_runner()
        for args in (['telegram', 'status'], ['telegram', 'test']):
            with _http(EX_HTTP, EX_HTTP):
                out = runner.invoke(args=args)
            assert TOKEN not in out.output, args


# ============================================================================ CLI

class TestCli:
    def test_status_sin_configurar(self, app):
        app.config.update(TELEGRAM_BOT_TOKEN=None, TELEGRAM_ALERT_CHAT_IDS=())
        out = app.test_cli_runner().invoke(args=['telegram', 'status']).output
        assert 'NO (TELEGRAM_BOT_TOKEN vacío)' in out and 'avisos activos    : NO' in out

    def test_status_configurado_enmascara_los_chats(self, tgcfg, db_session):
        _item(db_session)
        out = tgcfg.test_cli_runner().invoke(args=['telegram', 'status']).output
        assert 'token configurado : sí' in out and '…111, …222' in out and '1111111' not in out and 'pendientes de avisar ahora: 1' in out

    def test_test_envia_y_muestra_el_bot(self, tgcfg, db_session):
        get_me = _resp(200, {'ok': True, 'result': {'id': 1, 'is_bot': True, 'username': 'soc_bot', 'first_name': 'SOC'}})
        with _http(get_me, OK, OK):
            r = tgcfg.test_cli_runner().invoke(args=['telegram', 'test'])
        assert r.exit_code == 0 and '@soc_bot' in r.output and '…111: enviado' in r.output

    def test_test_con_token_malo_falla_con_mensaje_claro(self, tgcfg, db_session):
        with _http(R401):
            r = tgcfg.test_cli_runner().invoke(args=['telegram', 'test'])
        assert r.exit_code != 0 and 'El token no sirve' in r.output

    def test_test_sin_poder_escribir_a_ningun_chat(self, tgcfg, db_session):
        get_me = _resp(200, {'ok': True, 'result': {'username': 'soc_bot', 'first_name': 'SOC'}})
        with _http(get_me, R403, R403):
            r = tgcfg.test_cli_runner().invoke(args=['telegram', 'test'])
        assert r.exit_code != 0 and 'FALLÓ' in r.output

    def test_test_sin_configurar(self, app):
        app.config.update(TELEGRAM_BOT_TOKEN=None, TELEGRAM_ALERT_CHAT_IDS=())
        assert app.test_cli_runner().invoke(args=['telegram', 'test']).exit_code != 0

    def test_feeds_run_avisa_si_esta_configurado(self, tgcfg, db_session):
        with patch.object(feed_runner, 'run_source', return_value={'source': 'x', 'status': 'ok'}), \
                patch.object(feed_notifier, 'notify_pending', return_value={'status': 'sent', 'items': 2}):
            out = tgcfg.test_cli_runner().invoke(args=['feeds', 'run']).output
        assert 'avisos Telegram: sent (2 CVE)' in out

    def test_feeds_run_no_menciona_telegram_si_esta_desactivado(self, app, db_session):
        app.config.update(TELEGRAM_BOT_TOKEN=None, TELEGRAM_ALERT_CHAT_IDS=())
        with patch.object(feed_runner, 'run_source', return_value={'source': 'x', 'status': 'ok'}):
            assert 'Telegram' not in app.test_cli_runner().invoke(args=['feeds', 'run']).output


# ============================================================================ CONFIGURACIÓN

class TestConfiguracion:
    def _recargar(self, monkeypatch, **env):
        for k in ('TELEGRAM_BOT_TOKEN', 'TELEGRAM_ALERT_CHAT_IDS', 'TELEGRAM_MIN_RISK', 'TELEGRAM_BACKLOG_DAYS', 'APP_BASE_URL'):
            monkeypatch.delenv(k, raising=False)
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        from app import config
        return importlib.reload(config).Config

    def test_por_defecto_desactivado(self, monkeypatch):
        c = self._recargar(monkeypatch)
        assert c.TELEGRAM_BOT_TOKEN is None and c.TELEGRAM_ALERT_CHAT_IDS == () and c.TELEGRAM_MIN_RISK == 'ALTO' and c.TELEGRAM_BACKLOG_DAYS == 3
        importlib.reload(importlib.import_module('app.config'))

    def test_chats_con_espacios_y_grupos_negativos_e_invalidos(self, monkeypatch):
        c = self._recargar(monkeypatch, TELEGRAM_ALERT_CHAT_IDS=' 123 , -1001234567 ,abc, ,45x')
        assert c.TELEGRAM_ALERT_CHAT_IDS == (123, -1001234567)
        importlib.reload(importlib.import_module('app.config'))

    def test_base_url_sin_barra_final(self, monkeypatch):
        c = self._recargar(monkeypatch, APP_BASE_URL='https://soc.example.org///')
        assert c.APP_BASE_URL == 'https://soc.example.org'
        importlib.reload(importlib.import_module('app.config'))


# ============================================================================ DESPLIEGUE Y DOCUMENTACIÓN

class TestDocumentacion:
    def test_las_variables_estan_en_env_example(self):
        from pathlib import Path
        txt = (Path(__file__).resolve().parents[2] / '.env.example').read_text(encoding='utf-8')
        for v in ('TELEGRAM_BOT_TOKEN', 'TELEGRAM_ALERT_CHAT_IDS', 'TELEGRAM_MIN_RISK', 'APP_BASE_URL'):
            assert v in txt
        assert not any(l.startswith('TELEGRAM_BOT_TOKEN=') and len(l.split('=', 1)[1].strip()) > 0 for l in txt.splitlines())   # sin valor real
