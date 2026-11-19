"""
Desbloqueo manual de cuentas bloqueadas por intentos de login fallidos.

Cubre: la regla (el evento 'account_unlocked' reinicia el contador SIN borrar los fallos), el listado,
la API solo-admin, la CLI y la UI. Cada prueba de "ahora funciona" tiene su control de "antes no".
"""
from datetime import timedelta

import pytest
from unittest.mock import patch
from click.testing import CliRunner

from app.models.audit import AuditEvent
from app.utils.login_throttle import (
    LOCKOUT_THRESHOLD, lockout_remaining, locked_accounts, unlock_account,
)
from app.utils.time_utils import utcnow


def _fallos(db_session, username, n, minutes_ago=1, ip='10.1.2.3'):
    for _ in range(n):
        db_session.session.add(AuditEvent(
            action='login_failed', success=False, ip_address=ip,
            created_at=utcnow() - timedelta(minutes=minutes_ago), details={'username': username}))
    db_session.session.commit()


def _login(client, username, password):
    return client.post('/auth/login', data={'username': username, 'password': password})


class TestReglaDeDesbloqueo:
    def test_control_sin_desbloqueo_la_cuenta_sigue_bloqueada(self, app, db_session):
        _fallos(db_session, 'ana', LOCKOUT_THRESHOLD)
        assert lockout_remaining('ana') is not None

    def test_desbloquear_reinicia_el_contador(self, app, db_session):
        _fallos(db_session, 'ana', LOCKOUT_THRESHOLD)
        r = unlock_account('ana', by='test')
        assert r == {'username': 'ana', 'was_locked': True}
        assert lockout_remaining('ana') is None

    def test_conserva_el_rastro_de_los_fallos(self, app, db_session):
        """La auditoría es de solo inserción: desbloquear AÑADE un evento, no borra los fallos."""
        _fallos(db_session, 'ana', LOCKOUT_THRESHOLD)
        unlock_account('ana', by='test')
        assert AuditEvent.query.filter_by(action='login_failed').count() == LOCKOUT_THRESHOLD
        assert AuditEvent.query.filter_by(action='account_unlocked').count() == 1

    def test_un_fallo_nuevo_tras_desbloquear_no_rebloquea(self, app, db_session):
        _fallos(db_session, 'ana', LOCKOUT_THRESHOLD)
        unlock_account('ana', by='test')
        _fallos(db_session, 'ana', 1, minutes_ago=0)
        assert lockout_remaining('ana') is None

    def test_vuelve_a_bloquear_tras_otros_cinco_fallos(self, app, db_session):
        _fallos(db_session, 'ana', LOCKOUT_THRESHOLD, minutes_ago=3)
        unlock_account('ana', by='test')
        # el desbloqueo es "ahora"; los fallos nuevos deben ser posteriores a él
        db_session.session.commit()
        for _ in range(LOCKOUT_THRESHOLD):
            db_session.session.add(AuditEvent(action='login_failed', success=False,
                                              created_at=utcnow() + timedelta(seconds=5),
                                              details={'username': 'ana'}))
        db_session.session.commit()
        assert lockout_remaining('ana', now=utcnow() + timedelta(seconds=10)) is not None

    def test_solo_desbloquea_a_ese_usuario(self, app, db_session):
        _fallos(db_session, 'ana', LOCKOUT_THRESHOLD)
        _fallos(db_session, 'beto', LOCKOUT_THRESHOLD)
        unlock_account('ana', by='test')
        assert lockout_remaining('ana') is None
        assert lockout_remaining('beto') is not None

    def test_no_distingue_mayusculas_ni_espacios(self, app, db_session):
        _fallos(db_session, 'ana', LOCKOUT_THRESHOLD)
        unlock_account('  ANA ', by='test')
        assert lockout_remaining('ana') is None

    def test_idempotente_y_audita_aunque_no_estuviera_bloqueada(self, app, db_session):
        r = unlock_account('nadie', by='test')
        assert r['was_locked'] is False
        assert AuditEvent.query.filter_by(action='account_unlocked').count() == 1

    def test_username_vacio(self, app, db_session):
        with pytest.raises(ValueError):
            unlock_account('   ', by='test')

    def test_si_la_auditoria_falla_no_finge_exito(self, app, db_session, monkeypatch):
        """AuditEvent.log falla en silencio (devuelve None): aquí eso sería un desbloqueo falso."""
        monkeypatch.setattr(AuditEvent, 'log', classmethod(lambda cls, *a, **k: None))
        with pytest.raises(RuntimeError):
            unlock_account('ana', by='test')

    def test_se_puede_iniciar_sesion_tras_desbloquear(self, app, db_session, client, analyst_user):
        for _ in range(LOCKOUT_THRESHOLD):
            _login(client, 'test_analyst', 'mala-mala-mala')
        assert _login(client, 'test_analyst', 'AnalystPass123!').status_code == 429     # control
        unlock_account('test_analyst', by='test')
        assert _login(client, 'test_analyst', 'AnalystPass123!').status_code == 302


class TestListado:
    def test_lista_solo_las_bloqueadas(self, app, db_session):
        _fallos(db_session, 'ana', LOCKOUT_THRESHOLD, ip='9.9.9.9')
        _fallos(db_session, 'beto', LOCKOUT_THRESHOLD - 1)
        cuentas = locked_accounts()
        assert [c['username'] for c in cuentas] == ['ana']
        assert cuentas[0]['fallos'] == LOCKOUT_THRESHOLD
        assert cuentas[0]['ultima_ip'] == '9.9.9.9'
        assert cuentas[0]['restante_min'] >= 1

    def test_una_desbloqueada_ya_no_aparece(self, app, db_session):
        _fallos(db_session, 'ana', LOCKOUT_THRESHOLD)
        assert locked_accounts()
        unlock_account('ana', by='test')
        assert locked_accounts() == []

    def test_vacio(self, app, db_session):
        assert locked_accounts() == []


class TestApi:
    def test_admin_lista_y_desbloquea(self, app, db_session, admin_client):
        _fallos(db_session, 'ana', LOCKOUT_THRESHOLD)
        r = admin_client.get('/api/v2/admin/locked-accounts')
        assert r.status_code == 200 and r.get_json()['count'] == 1
        r = admin_client.post('/api/v2/admin/accounts/unlock', json={'username': 'ana'})
        assert r.status_code == 200 and r.get_json()['was_locked'] is True
        assert lockout_remaining('ana') is None

    def test_el_evento_registra_al_admin_que_lo_hizo(self, app, db_session, admin_client, admin_user):
        _fallos(db_session, 'ana', LOCKOUT_THRESHOLD)
        admin_client.post('/api/v2/admin/accounts/unlock', json={'username': 'ana'})
        ev = AuditEvent.query.filter_by(action='account_unlocked').one()
        assert ev.user_id == admin_user.id and ev.details['username'] == 'ana'

    @pytest.mark.parametrize('cliente', ['analyst_client', 'other_client'])
    def test_no_admin_recibe_403_y_no_desbloquea(self, app, db_session, request, cliente):
        _fallos(db_session, 'ana', LOCKOUT_THRESHOLD)
        c = request.getfixturevalue(cliente)
        assert c.get('/api/v2/admin/locked-accounts').status_code == 403
        assert c.post('/api/v2/admin/accounts/unlock', json={'username': 'ana'}).status_code == 403
        assert c.get('/admin/accounts').status_code == 403
        assert lockout_remaining('ana') is not None                      # control: sigue bloqueada

    def test_anonimo_no_accede(self, app, db_session, client):
        assert client.get('/api/v2/admin/locked-accounts').status_code in (302, 401)
        assert client.post('/api/v2/admin/accounts/unlock', json={'username': 'ana'}).status_code in (302, 401)

    @pytest.mark.parametrize('cuerpo', [{}, {'username': ''}, {'username': 5}, {'username': ['a']}, None])
    def test_cuerpo_invalido_400(self, admin_client, cuerpo):
        r = admin_client.post('/api/v2/admin/accounts/unlock', json=cuerpo)
        assert r.status_code == 400

    def test_username_demasiado_largo_400(self, admin_client):
        r = admin_client.post('/api/v2/admin/accounts/unlock', json={'username': 'a' * 500})
        assert r.status_code == 400


class TestCli:
    def test_unlock_y_locked(self, app, db_session):
        _fallos(db_session, 'ana', LOCKOUT_THRESHOLD)
        runner = app.test_cli_runner()
        out = runner.invoke(args=['accounts', 'locked'])
        assert out.exit_code == 0 and 'ana' in out.output
        out = runner.invoke(args=['accounts', 'unlock', 'ana'])
        assert out.exit_code == 0 and 'Desbloqueada' in out.output
        assert lockout_remaining('ana') is None
        ev = AuditEvent.query.filter_by(action='account_unlocked').one()
        assert ev.username.startswith('cli:')
        assert 'Ninguna' in runner.invoke(args=['accounts', 'locked']).output

    def test_unlock_vacio_falla_limpio(self, app, db_session):
        out = app.test_cli_runner().invoke(args=['accounts', 'unlock', '  '])
        assert out.exit_code != 0


class TestUi:
    def test_pagina_para_admin_con_nonce_y_sin_handlers_inline(self, admin_client):
        html = admin_client.get('/admin/accounts').get_data(as_text=True)
        assert 'Cuentas bloqueadas' in html
        assert 'onclick=' not in html
        assert '<script nonce=' in html

    def test_enlace_de_barra_lateral_solo_para_admin(self, admin_client, analyst_client):
        assert '/admin/accounts' in admin_client.get('/dashboard').get_data(as_text=True)
        assert '/admin/accounts' not in analyst_client.get('/dashboard').get_data(as_text=True)



class TestListadoEscalable:
    """S-3: un atacante que pruebe nombres aleatorios encarecía la página con 1 + 2 consultas POR NOMBRE."""

    def test_solo_evalua_los_nombres_cerca_del_umbral(self, app, db_session):
        for i in range(60):                                        # 60 nombres con 1 fallo (ruido de un atacante)
            _fallos(db_session, f'ruido{i}', 1)
        _fallos(db_session, 'casi', LOCKOUT_THRESHOLD - 1)        # 4 fallos: no puede estar bloqueado
        _fallos(db_session, 'bloqueado', LOCKOUT_THRESHOLD)
        import app.utils.login_throttle as lt
        reales = lt.lockout_remaining
        llamadas = []

        def espia(u, now=None):
            llamadas.append(u)
            return reales(u, now)

        with patch.object(lt, 'lockout_remaining', side_effect=espia):
            cuentas = lt.locked_accounts()
        assert [c['username'] for c in cuentas] == ['bloqueado'] and llamadas == ['bloqueado']

    def test_control_un_login_correcto_o_desbloqueo_sigue_reiniciando_la_cuenta(self, app, db_session):
        """El prefiltro es una condición NECESARIA: la regla exacta sigue en lockout_remaining."""
        _fallos(db_session, 'ana', LOCKOUT_THRESHOLD)
        assert [c['username'] for c in locked_accounts()] == ['ana']
        unlock_account('ana', by='test')
        assert locked_accounts() == []
