"""
Cadena criptográfica de la auditoría (WP1 de PLAN-FUSION).

Los ataques se hacen con SQL directo contra PostgreSQL REAL, con el trigger desactivado (lo que haría alguien con permisos de propietario
de la tabla: el caso que la cadena existe para detectar). Cada ataque tiene su control: la misma cadena sin tocar verifica `ok`.
"""
import ast
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import text

from app import db
from app.models.audit import AuditEvent
from app.services import audit_chain as ac
from app.services import telegram_client as tg
from app.utils.time_utils import utcnow

KEY = 'k' * 40
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def cadena(app, db_session):
    """Clave de prueba + trigger instalado y activo (la BD de test puede haberse creado con create_all, sin migración)."""
    antes = {k: app.config.get(k) for k in ('AUDIT_CHAIN_KEY', 'AUDIT_CHAIN_PREVIOUS_KEYS', 'AUDIT_CHAIN_ACCEPT_UNKEYED',
                                              'AUDIT_CHAIN_LOST_KEY_IDS', 'TELEGRAM_BOT_TOKEN', 'TELEGRAM_ALERT_CHAT_IDS')}
    app.config.update(AUDIT_CHAIN_KEY=KEY, AUDIT_CHAIN_PREVIOUS_KEYS=None, AUDIT_CHAIN_ACCEPT_UNKEYED=None, AUDIT_CHAIN_LOST_KEY_IDS=None,
                      TELEGRAM_BOT_TOKEN=None, TELEGRAM_ALERT_CHAT_IDS=())
    ac.reset_backoff()
    db.session.execute(text(ac.GUARD_FUNCTION_SQL))
    db.session.execute(text('DROP TRIGGER IF EXISTS trg_audit_events_guard ON audit_events'))
    db.session.execute(text(ac.GUARD_TRIGGER_SQL))
    db.session.commit()
    yield
    db.session.rollback()
    app.config.update(antes)
    ac.reset_backoff()


def _log(n=5, prefix='ev', **kw):
    for i in range(n):
        AuditEvent.log(f'{prefix}{i}', resource_type='t', resource_id=i, details={'i': i, 'txt': 'ñandú'}, _commit=True, **kw)


@contextmanager
def sin_trigger():
    """Lo que puede hacer quien es propietario de la tabla: apagar el trigger, atacar y dejarlo como estaba."""
    db.session.commit()
    db.session.execute(text('ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_guard'))
    db.session.commit()
    try:
        yield
    finally:
        db.session.rollback()
        db.session.execute(text('ALTER TABLE audit_events ENABLE TRIGGER trg_audit_events_guard'))
        db.session.commit()


def _sql(sql, **p):
    with sin_trigger():
        db.session.execute(text(sql), p)
        db.session.commit()


def _ok():
    return ac.verify_chain()


def _roto(res, pos=None):
    assert not res['ok'], res
    if pos is not None:
        assert res['broken']['pos'] == pos, res['broken']
    return res['broken']


# ============================================================================ SELLADO

class TestSellado:
    def test_encadena_desde_el_genesis(self):
        _log(4)
        rows = AuditEvent.query.order_by(AuditEvent.chain_pos).all()
        assert [r.chain_pos for r in rows] == [1, 2, 3, 4]
        assert rows[0].prev_hash == ac.GENESIS and all(rows[i].prev_hash == rows[i - 1].entry_hash for i in range(1, 4))
        assert all(len(r.entry_hash) == 64 and r.algo == 'v1' and r.key_id == ac.key_id(KEY.encode()) for r in rows)
        assert _ok()['ok'] and _ok()['checked'] == 4

    def test_varios_eventos_en_un_mismo_flush_se_encadenan_en_orden_de_creacion(self):
        for i in range(5):
            AuditEvent.log(f'a{i}')                           # sin commit: los 5 entran en el mismo flush
        db.session.commit()
        assert [r.action for r in AuditEvent.query.order_by(AuditEvent.chain_pos)] == [f'a{i}' for i in range(5)]
        assert _ok()['ok']

    def test_un_rollback_no_deja_huecos(self):
        _log(2)
        AuditEvent.log('descartado')
        db.session.flush()
        db.session.rollback()
        _log(2, prefix='x')
        assert [r.chain_pos for r in AuditEvent.query.order_by(AuditEvent.chain_pos)] == [1, 2, 3, 4]
        assert _ok()['ok']

    def test_log_conserva_su_contrato_y_los_valores_por_defecto(self):
        e = AuditEvent.log('x', _commit=True)
        assert e.id and e.created_at is not None and e.success is True and e.chain_pos == 1

    def test_el_sello_cubre_el_contenido_completo_de_la_fila(self):
        """Cambiar CUALQUIER columna persistida altera el hash (mutación de cada campo)."""
        base = dict(username='ana', action='a', resource_type='ioc', resource_id=1, details={'k': 1}, ip_address='1.2.3.4',
                    user_agent='ua', request_id='r', success=True, created_at=utcnow())
        h0 = ac.compute_hash(KEY.encode(), 1, ac.GENESIS, base)
        for campo, nuevo in [('username', 'bob'), ('action', 'b'), ('resource_type', 'x'), ('resource_id', 2), ('details', {'k': 2}),
                             ('ip_address', '1.2.3.5'), ('user_agent', 'ub'), ('request_id', 's'), ('success', False),
                             ('created_at', base['created_at'] + timedelta(microseconds=1))]:
            assert ac.compute_hash(KEY.encode(), 1, ac.GENESIS, {**base, campo: nuevo}) != h0, campo
        assert ac.compute_hash(KEY.encode(), 2, ac.GENESIS, base) != h0                      # la posición
        assert ac.compute_hash(KEY.encode(), 1, 'f' * 64, base) != h0                        # el eslabón anterior
        assert ac.compute_hash(b'otra-clave', 1, ac.GENESIS, base) != h0                     # la clave
        assert ac.compute_hash(None, 1, ac.GENESIS, base) != h0                              # HMAC != SHA-256 simple

    @pytest.mark.parametrize('details', [
        None, {}, {'a': 1}, {'z': 1, 'a': {'y': [1, 2, {'q': None}]}}, {'f': 1.0}, {'f': 1e22}, {'f': 0.1}, {'f': 1e-7}, {'f': -0.0},
        {'n': 2 ** 63 + 5}, {'t': True, 'f': False}, {'u': 'ñandú 😀   "comillas" \\ barra'}, {'k': ''}, {'lista': []},
        {'anidado': {'a': {'b': {'c': [1.5, 'x', None]}}}}, {'1': 'clave numerica'}, {'big': 123456789012345678901234567890},
    ])
    def test_el_hash_sobrevive_al_viaje_por_jsonb(self, details):
        """JSONB reordena claves y normaliza números (1e22 vuelve como entero): el canónico debe dar lo mismo antes y después."""
        AuditEvent.log('rt', details=details, _commit=True)
        db.session.expire_all()
        assert _ok()['ok'], details

    def test_columnas_en_su_limite(self):
        db.session.add(AuditEvent(action='a' * 80, username='ñ' * 80, resource_type='r' * 50, ip_address='2001:db8::' + 'f' * 20,
                                  user_agent='u' * 300, request_id='r' * 36))
        db.session.commit()
        db.session.expire_all()
        assert _ok()['ok']

    def test_una_fecha_con_zona_horaria_se_normaliza_a_utc_naive(self):
        from datetime import datetime, timezone
        e = AuditEvent(action='tz', created_at=datetime(2026, 1, 2, 3, 4, 5, 6, tzinfo=timezone(timedelta(hours=-6))))
        db.session.add(e)
        db.session.commit()
        db.session.expire_all()
        assert AuditEvent.query.one().created_at == datetime(2026, 1, 2, 9, 4, 5, 6) and _ok()['ok']

    def test_sin_clave_usa_sha256_simple_y_lo_marca(self, app):
        app.config['AUDIT_CHAIN_KEY'] = None
        _log(2)
        r = AuditEvent.query.order_by(AuditEvent.chain_pos).first()
        assert r.key_id == 'none' and _ok()['ok']

    def test_key_id_no_revela_la_clave(self):
        kid = ac.key_id(KEY.encode())
        assert len(kid) == 8 and KEY not in kid and ac.key_id(None) == 'none'


# ============================================================================ ATAQUES (con la cadena intacta como control)

class TestAtaques:
    @pytest.fixture(autouse=True)
    def cadena_de_6(self):
        _log(6)
        assert _ok()['ok'] and _ok()['checked'] == 6          # CONTROL: sin tocar, es íntegra

    @pytest.mark.parametrize('col,val', [('action', 'borrado_de_huellas'), ('username', 'otro'), ('resource_id', 99),
                                          ('success', False), ('ip_address', '6.6.6.6'), ('user_agent', 'x'),
                                          ('request_id', 'zz'), ('resource_type', 'q')])
    def test_editar_una_columna(self, col, val):
        _sql(f'UPDATE audit_events SET {col} = :v WHERE chain_pos = 3', v=val)
        _roto(_ok(), 3)

    def test_editar_los_detalles(self):
        _sql("UPDATE audit_events SET details = '{\"i\": 777}'::jsonb WHERE chain_pos = 4")
        assert 'editada' in _roto(_ok(), 4)['reason']

    def test_editar_la_fecha(self):
        _sql("UPDATE audit_events SET created_at = created_at - interval '1 day' WHERE chain_pos = 2")
        _roto(_ok(), 2)

    def test_borrar_una_fila_del_medio(self):
        _sql('DELETE FROM audit_events WHERE chain_pos = 3')
        b = _roto(_ok(), 3)
        assert 'falta' in b['reason']

    def test_borrar_el_inicio(self):
        _sql('DELETE FROM audit_events WHERE chain_pos = 1')
        _roto(_ok(), 1)

    def test_borrar_varias_filas_seguidas(self):
        _sql('DELETE FROM audit_events WHERE chain_pos IN (2, 3, 4)')
        _roto(_ok(), 2)

    def test_insertar_una_fila_falsa_sin_conocer_la_clave(self):
        """Con SHA-256 recalculado y haciéndose pasar por la clave real (key_id) no puede acertar el HMAC."""
        t = ac.tail()
        falsa = dict(username='x', action='falsa', resource_type=None, resource_id=None, details=None, ip_address=None,
                     user_agent=None, request_id=None, success=True, created_at=utcnow())
        h = ac.compute_hash(b'adivinada', t['pos'] + 1, t['hash'], falsa)
        _sql('INSERT INTO audit_events (username, action, success, created_at, chain_pos, prev_hash, entry_hash, key_id, algo) '
             'VALUES (:u, :a, true, :c, :p, :ph, :h, :k, :al)', u='x', a='falsa', c=falsa['created_at'], p=t['pos'] + 1, ph=t['hash'],
             h=h, k=ac.key_id(KEY.encode()), al='v1')
        assert 'editada' in _roto(_ok(), t['pos'] + 1)['reason']

    def test_insertar_una_fila_falsa_declarandola_sin_clave(self):
        """El hueco que cerré: key_id='none' con el hash SHA-256 correcto. Sin esta regla quedaba como 'no verificable' y pasaba."""
        t = ac.tail()
        falsa = dict(username='x', action='falsa', resource_type=None, resource_id=None, details=None, ip_address=None,
                     user_agent=None, request_id=None, success=True, created_at=utcnow())
        h = ac.compute_hash(None, t['pos'] + 1, t['hash'], falsa)
        _sql('INSERT INTO audit_events (username, action, success, created_at, chain_pos, prev_hash, entry_hash, key_id, algo) '
             'VALUES (:u, :a, true, :c, :p, :ph, :h, \'none\', \'v1\')', u='x', a='falsa', c=falsa['created_at'], p=t['pos'] + 1,
             ph=t['hash'], h=h)
        assert 'SIN clave' in _roto(_ok(), t['pos'] + 1)['reason']

    def test_insertar_una_fila_falsa_con_una_clave_desconocida(self):
        t = ac.tail()
        otra = b'o' * 40
        falsa = dict(username='x', action='falsa', resource_type=None, resource_id=None, details=None, ip_address=None,
                     user_agent=None, request_id=None, success=True, created_at=utcnow())
        _sql('INSERT INTO audit_events (username, action, success, created_at, chain_pos, prev_hash, entry_hash, key_id, algo) '
             'VALUES (:u, :a, true, :c, :p, :ph, :h, :k, \'v1\')', u='x', a='falsa', c=falsa['created_at'], p=t['pos'] + 1,
             ph=t['hash'], h=ac.compute_hash(otra, t['pos'] + 1, t['hash'], falsa), k=ac.key_id(otra))
        assert 'clave desconocida' in _roto(_ok(), t['pos'] + 1)['reason']

    def test_insertar_una_fila_sin_sellar(self):
        _sql("INSERT INTO audit_events (action, success, created_at) VALUES ('colada', true, now())")
        res = _roto(_ok())
        assert 'SIN sellar' in res['reason'] and _ok()['unsealed'] == 1

    def test_reordenar_dos_filas(self):
        with sin_trigger():
            db.session.execute(text('UPDATE audit_events SET chain_pos = 100 WHERE chain_pos = 3'))
            db.session.execute(text('UPDATE audit_events SET chain_pos = 3 WHERE chain_pos = 4'))
            db.session.execute(text('UPDATE audit_events SET chain_pos = 4 WHERE chain_pos = 100'))
            db.session.commit()
        _roto(_ok(), 3)

    def test_reescribir_toda_la_cadena_sin_la_clave(self):
        """El atacante edita una fila y recalcula TODOS los eslabones con SHA-256 y el key_id real: no acierta el HMAC."""
        with sin_trigger():
            rows = db.session.execute(text('SELECT * FROM audit_events ORDER BY chain_pos')).mappings().all()
            prev = ac.GENESIS
            for r in rows:
                f = dict(r)
                if r['chain_pos'] == 2:
                    f['action'] = 'reescrita'
                h = ac.compute_hash(b'sin-clave', r['chain_pos'], prev, f)
                db.session.execute(text('UPDATE audit_events SET action=:a, prev_hash=:p, entry_hash=:h WHERE id=:i'),
                                   {'a': f['action'], 'p': prev, 'h': h, 'i': r['id']})
                prev = h
            db.session.commit()
        _roto(_ok(), 1)

    def test_con_la_clave_robada_se_puede_falsificar_y_el_ancla_lo_limita(self):
        """LÍMITE DOCUMENTADO: quien tiene la clave rehace la cadena. Un ancla publicada antes lo delata (hash distinto en su posición)."""
        ancla = f"{ac.tail()['pos']}:{ac.tail()['hash']}"
        with sin_trigger():
            rows = db.session.execute(text('SELECT * FROM audit_events ORDER BY chain_pos')).mappings().all()
            prev = ac.GENESIS
            for r in rows:
                f = dict(r)
                if r['chain_pos'] == 2:
                    f['action'] = 'reescrita'
                h = ac.compute_hash(KEY.encode(), r['chain_pos'], prev, f)
                db.session.execute(text('UPDATE audit_events SET action=:a, prev_hash=:p, entry_hash=:h WHERE id=:i'),
                                   {'a': f['action'], 'p': prev, 'h': h, 'i': r['id']})
                prev = h
            db.session.commit()
        assert _ok()['ok'] is True                                       # sin ancla, el que tiene la clave sale impune...
        assert ac.verify_chain(ancla)['ok'] is False and 'ancla' in ac.verify_chain(ancla)['broken']['reason']   # ...con ancla, no

    def test_recalcular_un_solo_eslabon_con_la_clave_se_detecta_por_el_enlace(self):
        """Quien edita la fila 2 y recalcula SOLO su hash (sabiendo la clave) deja a la fila 3 apuntando al hash viejo."""
        with sin_trigger():
            r = dict(db.session.execute(text('SELECT * FROM audit_events WHERE chain_pos = 2')).mappings().one())
            r['action'] = 'reescrita'
            h = ac.compute_hash(KEY.encode(), 2, r['prev_hash'], r)
            db.session.execute(text('UPDATE audit_events SET action=:a, entry_hash=:h WHERE chain_pos = 2'), {'a': 'reescrita', 'h': h})
            db.session.commit()
        b = _roto(_ok(), 3)
        assert 'enlace' in b['reason']

    def test_truncar_la_cola_solo_lo_detecta_el_ancla(self):
        ancla = f"{ac.tail()['pos']}:{ac.tail()['hash']}"
        _sql('DELETE FROM audit_events WHERE chain_pos IN (5, 6)')
        assert _ok()['ok'] is True                                       # LÍMITE DOCUMENTADO: la cadena sola no ve el recorte
        r = ac.verify_chain(ancla)
        assert r['ok'] is False and 'se borraron las últimas filas' in r['broken']['reason']

    def test_ancla_correcta_y_ancla_con_hash_ajeno(self):
        t = ac.tail()
        assert ac.verify_chain(f"{t['pos']}:{t['hash']}")['anchor'] == 'ok'
        r = ac.verify_chain(f"{t['pos']}:{'a' * 64}")
        assert not r['ok'] and 'no tiene el hash del ancla' in r['broken']['reason']

    @pytest.mark.parametrize('malo', ['', 'abc', '5', '5:corto', '0:' + 'a' * 64, 'x:' + 'a' * 64, '5:' + 'z' * 64])
    def test_ancla_mal_formada(self, malo):
        with pytest.raises(ValueError):
            ac.parse_anchor(malo)

    def test_se_informa_la_primera_rotura(self):
        _sql("UPDATE audit_events SET action='a' WHERE chain_pos = 5")
        _sql("UPDATE audit_events SET action='b' WHERE chain_pos = 2")
        _roto(_ok(), 2)


# ============================================================================ ROTACIÓN DE CLAVE

class TestRotacion:
    def test_una_clave_anterior_declarada_sigue_verificando(self, app):
        _log(3)
        app.config.update(AUDIT_CHAIN_KEY='n' * 40, AUDIT_CHAIN_PREVIOUS_KEYS=KEY)
        _log(2, prefix='nueva')
        assert _ok()['ok'] and _ok()['checked'] == 5

    def test_sin_declarar_la_anterior_es_rotura(self, app):
        _log(3)
        app.config.update(AUDIT_CHAIN_KEY='n' * 40)
        assert 'clave desconocida' in _roto(_ok(), 1)['reason']

    def test_historico_sin_clave_se_acepta_solo_si_el_operador_lo_declara(self, app):
        app.config['AUDIT_CHAIN_KEY'] = None
        _log(3)
        app.config.update(AUDIT_CHAIN_KEY=KEY)
        assert 'SIN clave' in _roto(_ok(), 1)['reason']
        app.config['AUDIT_CHAIN_ACCEPT_UNKEYED'] = '3'            # tope: la última posición sin clave
        assert _ok()['ok']

    def test_aceptar_historico_sin_clave_no_exime_de_comprobar_su_contenido(self, app):
        app.config['AUDIT_CHAIN_KEY'] = None
        _log(3)
        app.config.update(AUDIT_CHAIN_KEY=KEY, AUDIT_CHAIN_ACCEPT_UNKEYED='3')
        _sql("UPDATE audit_events SET action='editada' WHERE chain_pos = 2")
        _roto(_ok(), 2)

    def test_clave_perdida_declarada_permite_seguir_sin_aceptar_cualquier_cosa(self, app):
        """Procedimiento de RUNBOOK-AUDIT-CHAIN.md: se pierde la clave, se pone una nueva y se declara el key_id perdido."""
        _log(3)
        perdida = ac.key_id(KEY.encode())
        app.config['AUDIT_CHAIN_KEY'] = 'n' * 40
        b = _roto(_ok(), 1)                                                            # CONTROL: sin declarar, es rotura
        assert 'AUDIT_CHAIN_LOST_KEY_IDS' in b['reason']                               # y el mensaje dice cómo resolverlo
        app.config['AUDIT_CHAIN_LOST_KEY_IDS'] = f'{perdida}:3'                      # con TOPE: la última posición legítima
        r = _ok()
        assert r['ok'] and r['unverifiable'] == 3                                      # honesto: 3 filas solo con enlace, no recalculadas
        _log(2, prefix='nueva')                                                        # lo nuevo se sella con la clave nueva...
        assert _ok()['ok'] and _ok()['checked'] == 5
        _sql("UPDATE audit_events SET action='editada' WHERE chain_pos = 5")           # ...y SÍ se protege su contenido
        _roto(_ok(), 5)

    def test_clave_perdida_declarada_sigue_detectando_huecos_y_enlaces(self, app):
        """Declarar una clave perdida NO desactiva el resto de comprobaciones (borrados, reordenación, filas sin sellar)."""
        _log(5)
        app.config.update(AUDIT_CHAIN_KEY='n' * 40, AUDIT_CHAIN_LOST_KEY_IDS=ac.key_id(KEY.encode()) + ':5')
        assert _ok()['ok']
        _sql('DELETE FROM audit_events WHERE chain_pos = 3')
        assert 'falta' in _roto(_ok(), 3)['reason']

    def test_limite_documentado_el_contenido_de_filas_de_clave_perdida_no_se_puede_comprobar(self, app):
        _log(3)
        app.config.update(AUDIT_CHAIN_KEY='n' * 40, AUDIT_CHAIN_LOST_KEY_IDS=ac.key_id(KEY.encode()) + ':3')
        _sql("UPDATE audit_events SET action='editada' WHERE chain_pos = 2")
        assert _ok()['ok'] is True                       # por eso el runbook pide anotar la pérdida y apoyarse en las anclas

    def test_declarar_otra_clave_como_perdida_no_acepta_la_forjada(self, app):
        _log(2)
        app.config['AUDIT_CHAIN_LOST_KEY_IDS'] = 'deadbeef:5'
        assert _ok()['ok']                               # la real sigue verificándose (no se confunde con la declarada)
        _sql("UPDATE audit_events SET action='x' WHERE chain_pos = 1")
        _roto(_ok(), 1)

    def _forjar_con_clave_perdida(self, kid, pos_extra=1):
        """Lo que haría una inyección SQL con INSERT: una fila enlazada con el key_id (público) de la clave perdida y un hash cualquiera."""
        t = ac.tail()
        falsa = dict(username='x', action='falsa', resource_type=None, resource_id=None, details=None, ip_address=None, user_agent=None,
                     request_id=None, success=True, created_at=utcnow())
        pos = t['pos'] + pos_extra
        h = ac.compute_hash(b'cualquiera', pos, t['hash'], falsa)
        _sql("INSERT INTO audit_events (username, action, success, created_at, chain_pos, prev_hash, entry_hash, key_id, algo) "
             "VALUES ('x', 'falsa', true, :c, :p, :ph, :h, :k, 'v1')", c=falsa['created_at'], p=pos, ph=t['hash'], h=h, k=kid)

    def test_clave_perdida_sin_tope_se_ignora(self, app):
        """M2: sin tope, el key_id (público) serviría para colar filas. Una entrada sin ':<posición>' no declara nada."""
        _log(3)
        app.config.update(AUDIT_CHAIN_KEY='n' * 40)
        for malo in (ac.key_id(KEY.encode()), ac.key_id(KEY.encode()) + ':', ac.key_id(KEY.encode()) + ':abc', ac.key_id(KEY.encode()) + ':0'):
            app.config['AUDIT_CHAIN_LOST_KEY_IDS'] = malo
            assert ac.lost_key_ids() == {} and not _ok()['ok'], malo

    def test_fila_forjada_con_la_clave_perdida_por_encima_del_tope_es_rotura(self, app):
        """EL ATAQUE de M2 (que antes pasaba): tras declarar la clave perdida, INSERT de una fila con ese key_id al final de la cadena."""
        _log(3)
        perdida = ac.key_id(KEY.encode())
        app.config.update(AUDIT_CHAIN_KEY='n' * 40, AUDIT_CHAIN_LOST_KEY_IDS=f'{perdida}:3')
        assert _ok()['ok']                                                    # CONTROL: lo legítimo sigue verificando
        self._forjar_con_clave_perdida(perdida)
        b = _roto(_ok(), 4)
        assert 'POR ENCIMA de su tope' in b['reason']

    def test_el_tope_exacto_se_acepta_y_el_siguiente_no(self, app):
        _log(4)
        perdida = ac.key_id(KEY.encode())
        app.config.update(AUDIT_CHAIN_KEY='n' * 40, AUDIT_CHAIN_LOST_KEY_IDS=f'{perdida}:3')
        _roto(_ok(), 4)                                                       # la 4 (legítima, pero por encima de lo declarado) NO pasa
        app.config['AUDIT_CHAIN_LOST_KEY_IDS'] = f'{perdida}:4'
        assert _ok()['ok']

    def test_historico_sin_clave_solo_hasta_su_tope_y_true_ya_no_vale(self, app):
        app.config['AUDIT_CHAIN_KEY'] = None
        _log(3)
        app.config.update(AUDIT_CHAIN_KEY=KEY, AUDIT_CHAIN_ACCEPT_UNKEYED='3')
        assert _ok()['ok']
        t = ac.tail()                                                         # forjar una fila "sin clave" por encima del tope
        falsa = dict(username='x', action='falsa', resource_type=None, resource_id=None, details=None, ip_address=None, user_agent=None,
                     request_id=None, success=True, created_at=utcnow())
        _sql("INSERT INTO audit_events (username, action, success, created_at, chain_pos, prev_hash, entry_hash, key_id, algo) "
             "VALUES ('x', 'falsa', true, :c, 4, :ph, :h, 'none', 'v1')", c=falsa['created_at'], ph=t['hash'], h=ac.compute_hash(None, 4, t['hash'], falsa))
        _roto(_ok(), 4)
        for no_valido in ('true', '1.5', '', '0', 'yes'):
            app.config['AUDIT_CHAIN_ACCEPT_UNKEYED'] = no_valido
            assert ac.accept_unkeyed_cap() is None, no_valido

    def test_las_pistas_sugieren_el_tope_del_primer_tramo_contiguo(self, app):
        _log(3)
        perdida = ac.key_id(KEY.encode())
        app.config['AUDIT_CHAIN_KEY'] = 'n' * 40
        _log(2, prefix='nueva')                                              # 4 y 5 con la clave nueva
        r = _ok()
        assert r['hints'][perdida] == {'first': 1, 'last_contiguous': 3}
        self._forjar_con_clave_perdida(perdida)                              # una fila suelta con la clave perdida DESPUÉS: no amplía el tramo
        assert _ok()['hints'][perdida] == {'first': 1, 'last_contiguous': 3}

    def test_la_linea_de_comandos_muestra_el_formato_del_tope(self, app):
        _log(3)
        app.config['AUDIT_CHAIN_KEY'] = 'n' * 40
        out = app.test_cli_runner().invoke(args=['audit', 'verify']).output
        assert f"AUDIT_CHAIN_LOST_KEY_IDS={ac.key_id(KEY.encode())}:3" in out and 'CONFIRMA el tope' in out

    def test_sin_clave_configurada_lo_sellado_con_clave_cuenta_como_no_verificable(self, app):
        _log(3)
        app.config['AUDIT_CHAIN_KEY'] = None
        r = _ok()
        assert r['ok'] and r['unverifiable'] == 3


# ============================================================================ TRIGGER (PostgreSQL real)

class TestTrigger:
    def test_bloquea_delete(self):
        _log(2)
        with pytest.raises(Exception, match='DELETE no permitido'):
            db.session.execute(text('DELETE FROM audit_events WHERE chain_pos = 1'))
        db.session.rollback()
        assert AuditEvent.query.count() == 2

    @pytest.mark.parametrize('col,val', [('action', "'x'"), ('details', "'{}'::jsonb"), ('created_at', 'now()'), ('success', 'false'),
                                          ('entry_hash', "'" + 'a' * 64 + "'"), ('chain_pos', '99'), ('username', "'x'")])
    def test_bloquea_update(self, col, val):
        _log(2)
        with pytest.raises(Exception, match='no permitido|no se puede resellar'):
            db.session.execute(text(f'UPDATE audit_events SET {col} = {val} WHERE chain_pos = 1'))
        db.session.rollback()

    def test_user_id_no_puede_cambiar_a_otro_usuario(self, admin_user, analyst_user):
        AuditEvent.log('x', user_id=admin_user.id, _commit=True)
        with pytest.raises(Exception, match='solo puede pasar a NULL'):
            db.session.execute(text('UPDATE audit_events SET user_id = :u'), {'u': analyst_user.id})
        db.session.rollback()

    def test_borrar_un_usuario_con_auditoria_funciona_y_la_cadena_sigue_integra(self, app, admin_user, analyst_user):
        """ON DELETE SET NULL hace un UPDATE interno sobre la auditoría: el trigger tiene que dejarlo pasar (y user_id no está en el hash)."""
        AuditEvent.log('del_a', user_id=analyst_user.id, username=analyst_user.username, _commit=True)
        AuditEvent.log('del_b', user_id=analyst_user.id, username=analyst_user.username, _commit=True)
        uid = analyst_user.id
        db.session.execute(text('DELETE FROM users WHERE id = :i'), {'i': uid})
        db.session.commit()
        assert AuditEvent.query.filter(AuditEvent.action.like('del_%')).filter(AuditEvent.user_id.isnot(None)).count() == 0
        assert AuditEvent.query.filter(AuditEvent.action.like('del_%')).count() == 2         # la auditoría sobrevive
        assert _ok()['ok']

    def test_control_sin_trigger_el_ataque_pasa(self):
        """Sin el trigger la edición se ejecuta (y solo la cadena la delata): el trigger es defensa en profundidad."""
        _log(2)
        _sql("UPDATE audit_events SET action='x' WHERE chain_pos = 1")
        assert AuditEvent.query.filter_by(chain_pos=1).one().action == 'x' and not _ok()['ok']

    def test_la_migracion_y_el_modulo_tienen_el_mismo_sql(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('mig_audit_chain', ROOT / 'migrations' / 'versions' / 'c9e1f3a5b7d8_audit_chain.py')
        mig = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mig)
        assert mig.GUARD_FUNCTION_SQL == ac.GUARD_FUNCTION_SQL and mig.GUARD_TRIGGER_SQL == ac.GUARD_TRIGGER_SQL
        assert 'DELETE' in mig.GUARD_FUNCTION_SQL                         # control: no comparamos dos cadenas vacías


# ============================================================================ LEGADO

class TestLegado:
    def _legado(self, n=3):
        for i in range(n):
            db.session.execute(text("INSERT INTO audit_events (action, details, success, created_at) VALUES (:a, '{\"i\": 1}'::jsonb, true, now())"),
                               {'a': f'viejo{i}'})
        db.session.commit()

    def test_las_filas_anteriores_se_detectan_y_se_sellan(self):
        self._legado()
        r = _ok()
        assert not r['ok'] and r['unsealed'] == 3
        assert ac.seal_legacy() == 3
        r = _ok()
        assert r['ok'] and r['unsealed'] == 0 and r['checked'] == 3
        assert {x.algo for x in AuditEvent.query} == {'v1-legacy'}

    def test_sellar_continua_tras_lo_ya_encadenado(self):
        _log(2)
        self._legado(2)
        ac.seal_legacy()
        assert [r.chain_pos for r in AuditEvent.query.order_by(AuditEvent.chain_pos)] == [1, 2, 3, 4] and _ok()['ok']

    def test_sellar_es_idempotente(self):
        self._legado()
        ac.seal_legacy()
        assert ac.seal_legacy() == 0 and _ok()['ok']

    def test_una_fila_sellada_no_se_puede_resellar(self):
        _log(2)
        with pytest.raises(Exception, match='no se puede resellar|no permitido'):
            db.session.execute(text("UPDATE audit_events SET entry_hash = :h WHERE chain_pos = 1"), {'h': 'b' * 64})
        db.session.rollback()


# ============================================================================ CONCURRENCIA REAL

class TestConcurrencia:
    def test_hilos_con_su_propia_sesion_no_dejan_huecos_ni_bifurcaciones(self, app):
        errores = []

        def trabajo(n):
            try:
                with app.app_context():
                    for i in range(8):
                        AuditEvent.log(f't{n}_{i}', _commit=True)
                    db.session.remove()
            except Exception as e:                         # pragma: no cover - lo reporta la aserción
                errores.append(repr(e))

        hilos = [threading.Thread(target=trabajo, args=(n,)) for n in range(8)]
        [h.start() for h in hilos]
        [h.join(60) for h in hilos]
        assert not errores, errores
        pos = [r.chain_pos for r in AuditEvent.query.order_by(AuditEvent.chain_pos)]
        assert pos == list(range(1, 65)) and _ok()['ok'] and _ok()['checked'] == 64

    def test_con_la_ventana_de_carrera_ensanchada_el_bloqueo_sigue_serializando(self, app):
        """Con 8 hilos rápidos la carrera casi nunca ocurre aunque no haya bloqueo (la mutación 'sin bloqueo' pasaba): se ensancha a propósito
        la ventana entre leer el extremo e insertar. Con el bloqueo no se pierde ni se duplica nada; sin él, UNIQUE(chain_pos) pierde eventos."""
        import time
        real = ac.compute_hash

        def lento(*a, **k):
            time.sleep(0.03)
            return real(*a, **k)

        errores = []

        def trabajo(n):
            try:
                with app.app_context():
                    for i in range(4):
                        if AuditEvent.log(f'w{n}_{i}', _commit=True) is None:
                            errores.append(f'perdido {n}_{i}')
                    db.session.remove()
            except Exception as e:
                errores.append(repr(e))

        with patch.object(ac, 'compute_hash', side_effect=lento):
            hilos = [threading.Thread(target=trabajo, args=(n,)) for n in range(6)]
            [h.start() for h in hilos]
            [h.join(120) for h in hilos]
        assert not errores, errores[:3]
        assert [r.chain_pos for r in AuditEvent.query.order_by(AuditEvent.chain_pos)] == list(range(1, 25)) and _ok()['ok']

    def test_procesos_distintos_tambien(self):
        """Como los 3 workers de Gunicorn + el daemon + la CLI: procesos reales, no hilos."""
        script = ("import os\nos.environ['FLASK_ENV']='testing'\nfrom dotenv import load_dotenv; load_dotenv('.env')\n"
                  "from app import create_app, db\nfrom app.models.audit import AuditEvent\n"
                  "app = create_app('testing'); app.config['AUDIT_CHAIN_KEY'] = os.environ['K']\n"
                  "with app.app_context():\n    for i in range(10):\n        AuditEvent.log('p%s_%s' % (os.environ['N'], i), _commit=True)\n")
        env = {**os.environ, 'K': KEY, 'PYTHONIOENCODING': 'utf-8'}
        procs = [subprocess.Popen([sys.executable, '-c', script], cwd=ROOT, env={**env, 'N': str(n)}, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE) for n in range(4)]
        salidas = [p.communicate(timeout=180) for p in procs]
        assert all(p.returncode == 0 for p in procs), [s[1].decode(errors='replace')[-400:] for s in salidas]
        db.session.expire_all()
        assert [r.chain_pos for r in AuditEvent.query.order_by(AuditEvent.chain_pos)] == list(range(1, 41)) and _ok()['ok']

    def test_control_sin_el_bloqueo_se_producen_duplicados(self):
        """Prueba de que el test de arriba NO es vacuo: sin serializar, dos transacciones leen el mismo extremo y chocan (UNIQUE)."""
        from flask import current_app
        app = current_app._get_current_object()
        barrera = threading.Barrier(2)

        def sin_bloqueo(session):
            fila = session.execute(text('SELECT chain_pos, entry_hash FROM audit_events WHERE chain_pos IS NOT NULL '
                                        'ORDER BY chain_pos DESC LIMIT 1')).first()
            barrera.wait(15)                                 # las dos han leído el MISMO extremo antes de insertar
            return (fila[0], fila[1]) if fila else (0, ac.GENESIS)

        resultados = []

        def trabajo():
            with app.app_context():
                resultados.append(AuditEvent.log('carrera', _commit=True))   # log() traga el error y devuelve None
                db.session.remove()

        with patch.object(ac, '_lock_and_tail', side_effect=sin_bloqueo):
            ts = [threading.Thread(target=trabajo) for _ in range(2)]
            [t.start() for t in ts]
            [t.join(40) for t in ts]
        assert sorted(r is None for r in resultados) == [False, True]       # UNIQUE(chain_pos) frenó la bifurcación: una se perdió
        assert AuditEvent.query.count() == 1


# ============================================================================ ANCLA POR TELEGRAM

OK = MagicMock(status_code=200, **{'json.return_value': {'ok': True, 'result': {'message_id': 1}}})


def _tg(app):
    app.config.update(TELEGRAM_BOT_TOKEN='123456789:AAFAKE_tokenSecretoQueNoDebeFiltrarse_xyz', TELEGRAM_ALERT_CHAT_IDS=(1111111,))


class TestAncla:
    def test_sin_telegram_no_hace_nada(self):
        _log(2)
        with patch.object(tg, 'http_post') as h:
            assert ac.maybe_anchor()['status'] == 'disabled'
        assert not h.called

    def test_publica_el_extremo_y_lo_registra_una_vez_al_dia(self, app):
        _tg(app)
        _log(3)
        ahora = utcnow()
        with patch.object(tg, 'http_post', return_value=OK) as h:
            assert ac.maybe_anchor(ahora)['status'] == 'sent'
            assert ac.maybe_anchor(ahora + timedelta(hours=1))['status'] == 'idle'          # ya se envió hoy
        t = h.call_args.kwargs['json']['text']
        assert h.call_count == 1 and 'cadena íntegra' in t and f"{3}:" in t
        ev = AuditEvent.query.filter_by(action=ac.ANCHOR_ACTION).one()
        assert ev.details['pos'] == 3 and len(ev.details['hash']) == 64 and ev.details['ok'] is True
        assert KEY not in t and KEY not in str(ev.details)                                    # la clave nunca sale
        with patch.object(tg, 'http_post', return_value=OK) as h2:
            assert ac.maybe_anchor(ahora + ac.ANCHOR_EVERY + timedelta(minutes=1))['status'] == 'sent'      # al día siguiente
        assert h2.call_count == 1 and _ok()['ok']

    def test_si_la_cadena_esta_rota_el_aviso_lo_dice(self, app):
        _tg(app)
        _log(4)
        _sql("UPDATE audit_events SET action='x' WHERE chain_pos = 2")
        with patch.object(tg, 'http_post', return_value=OK) as h:
            r = ac.maybe_anchor()
        t = h.call_args.kwargs['json']['text']
        assert r['status'] == 'sent' and r['ok'] is False and 'CADENA ROTA' in t and 'eslabón 2' in t

    def test_un_fallo_de_telegram_reintenta_con_espera_y_no_registra(self, app):
        _tg(app)
        _log(2)
        ahora = utcnow()
        with patch.object(tg, 'http_post', side_effect=ConnectionError('caída')):
            assert ac.maybe_anchor(ahora)['status'] == 'retry'
        assert AuditEvent.query.filter_by(action=ac.ANCHOR_ACTION).count() == 0
        with patch.object(tg, 'http_post') as h:
            assert ac.maybe_anchor(ahora + timedelta(minutes=2))['status'] == 'backoff' and not h.called
        with patch.object(tg, 'http_post', return_value=OK):
            assert ac.maybe_anchor(ahora + ac.RETRY_BACKOFF)['status'] == 'sent'

    def test_cadena_vacia_no_envia(self, app):
        _tg(app)
        with patch.object(tg, 'http_post') as h:
            assert ac.maybe_anchor()['status'] == 'idle' and not h.called

    def test_el_daemon_la_invoca_cada_ciclo_y_no_muere_si_falla(self, app):
        from app.services import feed_notifier, feed_runner
        ciclos = {'n': 0}
        with patch.object(feed_runner, 'run_due', return_value=[]), patch.object(feed_notifier, 'maybe_notify',
                                                                                  return_value={'status': 'idle'}), \
                patch.object(ac, 'maybe_anchor', side_effect=[RuntimeError('x'), {'status': 'idle'}]) as ma:
            feed_runner.daemon(poll_seconds=1, stop=lambda: ciclos['n'] >= 2, sleep=lambda s: ciclos.__setitem__('n', ciclos['n'] + 1))
        assert ma.call_count == 2


# ============================================================================ CLI Y ENDPOINT

class TestCli:
    def test_status_no_imprime_la_clave(self, app):
        _log(2)
        out = app.test_cli_runner().invoke(args=['audit', 'status']).output
        assert KEY not in out and 'key_id' in out and '2:' in out and 'filas sin sellar      : 0' in out

    def test_verify_integra_y_rota(self, app):
        _log(3)
        r = app.test_cli_runner().invoke(args=['audit', 'verify'])
        assert r.exit_code == 0 and 'cadena ÍNTEGRA' in r.output
        _sql("UPDATE audit_events SET action='x' WHERE chain_pos = 2")
        r = app.test_cli_runner().invoke(args=['audit', 'verify'])
        assert r.exit_code == 1 and 'CADENA ROTA' in r.output and 'eslabón 2' in r.output

    def test_verify_con_ancla(self, app):
        _log(3)
        t = ac.tail()
        assert 'ancla                 : ok' in app.test_cli_runner().invoke(args=['audit', 'verify', '--anchor', f"{t['pos']}:{t['hash']}"]).output
        r = app.test_cli_runner().invoke(args=['audit', 'verify', '--anchor', 'basura'])
        assert r.exit_code != 0 and 'forma' in r.output

    def test_anchor_imprime_pos_y_hash(self, app):
        _log(3)
        assert app.test_cli_runner().invoke(args=['audit', 'anchor']).output.strip() == f"{ac.tail()['pos']}:{ac.tail()['hash']}"

    def test_anchor_con_cadena_vacia(self, app):
        assert app.test_cli_runner().invoke(args=['audit', 'anchor']).exit_code != 0

    def test_seal_legacy(self, app):
        db.session.execute(text("INSERT INTO audit_events (action, success, created_at) VALUES ('viejo', true, now())"))
        db.session.commit()
        assert '1 fila(s)' in app.test_cli_runner().invoke(args=['audit', 'seal-legacy']).output and _ok()['ok']


class TestEndpoint:
    def test_admin_verifica(self, admin_client):
        _log(3)
        r = admin_client.get('/api/v2/admin/audit/verify')
        j = r.get_json()
        assert r.status_code == 200 and j['ok'] is True and j['checked'] >= 3 and KEY not in r.get_data(as_text=True)

    def test_cadena_rota_es_200_con_ok_false(self, admin_client):
        _log(4)
        _sql("UPDATE audit_events SET action='x' WHERE chain_pos = 2")
        r = admin_client.get('/api/v2/admin/audit/verify')
        assert r.status_code == 200 and r.get_json()['ok'] is False and r.get_json()['broken']['pos'] == 2

    def test_ancla_en_la_consulta(self, admin_client):
        _log(3)
        t = ac.tail()
        assert admin_client.get(f"/api/v2/admin/audit/verify?anchor={t['pos']}:{t['hash']}").get_json()['anchor'] == 'ok'
        assert admin_client.get('/api/v2/admin/audit/verify?anchor=mala').status_code == 400

    def test_solo_admin(self, analyst_client, client):
        assert analyst_client.get('/api/v2/admin/audit/verify').status_code == 403
        assert client.get('/api/v2/admin/audit/verify').status_code in (401, 302)


# ============================================================================ CONFIGURACIÓN Y GUARDAS

class TestConfiguracion:
    @pytest.mark.parametrize('valor', [None, '', 'corta', 'x' * 31])
    def test_produccion_exige_la_clave(self, monkeypatch, valor):
        from app.config import ProductionConfig
        monkeypatch.setenv('SECRET_KEY', 's' * 40)
        monkeypatch.setenv('DATABASE_URL', 'postgresql://u:p@h/d')
        if valor is None:
            monkeypatch.delenv('AUDIT_CHAIN_KEY', raising=False)
        else:
            monkeypatch.setenv('AUDIT_CHAIN_KEY', valor)
        with pytest.raises(RuntimeError, match='AUDIT_CHAIN_KEY'):
            ProductionConfig.init_app()

    def test_produccion_arranca_con_la_clave(self, monkeypatch):
        from app.config import ProductionConfig
        monkeypatch.setenv('SECRET_KEY', 's' * 40)
        monkeypatch.setenv('DATABASE_URL', 'postgresql://u:p@h/d')
        monkeypatch.setenv('AUDIT_CHAIN_KEY', 'k' * 32)
        ProductionConfig.init_app()                                      # no lanza

    def test_las_variables_estan_documentadas(self):
        env = (ROOT / '.env.example').read_text(encoding='utf-8')
        assert 'AUDIT_CHAIN_KEY' in env
        assert not any(l.startswith('AUDIT_CHAIN_KEY=') and l.split('=', 1)[1].strip() for l in env.splitlines())    # sin valor real

    def test_docker_compose_y_verify_pasan_la_clave(self):
        # el env_file ya la trae del .env.docker; verify_docker.sh debe generarla o el stack de verificación no arrancaría
        assert 'AUDIT_CHAIN_KEY' in (ROOT / 'scripts' / 'ops' / 'verify_docker.sh').read_text(encoding='utf-8')


class TestGuardaDeContencion:
    """El bloqueo de la cadena se mantiene hasta el fin de la transacción: una llamada a AuditEvent.log que NO comitee y siga
    trabajando bloquearía a todas las demás. Hoy solo estas llamadas no comitean (y comitean justo después); una nueva hace fallar el test."""
    CONOCIDAS = {'app/routes/feed_routes.py': 2, 'app/services/feed_notifier.py': 1, 'app/utils/login_throttle.py': 1}

    def _llamadas(self):
        con, sin = 0, {}
        for f in (ROOT / 'app').rglob('*.py'):
            tree = ast.parse(f.read_text(encoding='utf-8'))
            for n in ast.walk(tree):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == 'log' \
                        and isinstance(n.func.value, ast.Name) and n.func.value.id == 'AuditEvent':
                    if any(k.arg == '_commit' and isinstance(k.value, ast.Constant) and k.value.value is True for k in n.keywords):
                        con += 1
                    else:
                        rel = f.relative_to(ROOT).as_posix()
                        sin[rel] = sin.get(rel, 0) + 1
        return con, sin

    def test_no_hay_llamadas_nuevas_sin_commit(self):
        con, sin = self._llamadas()
        assert con >= 25, 'el detector no encuentra las llamadas con _commit=True: sería vacuo'      # control
        assert sin == self.CONOCIDAS, f'AuditEvent.log sin _commit=True nuevo: revisa que comitee enseguida. {sin}'
