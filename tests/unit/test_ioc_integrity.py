"""
Regresión de CRIT-06 / ALTO-16 (migraciones c2d4e6f8a0b1 y d3e5f7a9b1c2):
  * uq_ioc_value_type existe de verdad en la BD (antes solo estaba en el modelo)
  * IOC.get_or_create es atómico ante la carrera check-then-insert (TOCTOU)
  * borrar un usuario no bloquea ni destruye sus análisis (FK ON DELETE SET NULL)
"""
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.models.ioc import IOC, IOCAnalysis, User


class TestUniqueConstraintEnBD:
    def test_constraint_existe_en_postgres(self, app, db_session):
        row = db_session.session.execute(text(
            "select pg_get_constraintdef(oid) from pg_constraint "
            "where conrelid='iocs'::regclass and conname='uq_ioc_value_type'")).scalar()
        assert row == 'UNIQUE (value, ioc_type)'

    def test_la_bd_rechaza_duplicados(self, app, db_session):
        db_session.session.add(IOC(value='203.0.113.1', ioc_type='ip'))
        db_session.session.commit()
        db_session.session.add(IOC(value='203.0.113.1', ioc_type='ip'))
        with pytest.raises(IntegrityError):
            db_session.session.commit()
        db_session.session.rollback()

    def test_mismo_valor_distinto_tipo_es_valido(self, app, db_session):
        db_session.session.add_all([IOC(value='example.test', ioc_type='domain'),
                                    IOC(value='example.test', ioc_type='url')])
        db_session.session.commit()          # no debe lanzar


class TestGetOrCreate:
    def test_crea_y_luego_reutiliza(self, app, db_session):
        a, created_a = IOC.get_or_create('198.51.100.9', 'ip')
        db_session.session.commit()
        b, created_b = IOC.get_or_create('198.51.100.9', 'ip')
        assert created_a is True and created_b is False
        assert a.id == b.id
        assert IOC.query.filter_by(value='198.51.100.9', ioc_type='ip').count() == 1

    def test_aplica_defaults_solo_al_crear(self, app, db_session):
        a, _ = IOC.get_or_create('198.51.100.10', 'ip', times_analyzed=0)
        db_session.session.commit()
        b, _ = IOC.get_or_create('198.51.100.10', 'ip', times_analyzed=99)
        assert b.times_analyzed == 0

    def test_carrera_toctou_devuelve_el_ganador_sin_500(self, app, db_session):
        """
        Simula la carrera: el SELECT del perdedor no ve nada (otra petición aún no había
        confirmado), pero el INSERT choca con uq_ioc_value_type en Postgres.
        """
        winner = IOC(value='198.51.100.20', ioc_type='ip')
        db_session.session.add(winner)
        db_session.session.commit()

        real_query = IOC.query
        fake_q = MagicMock()
        # 1ª consulta (check): "no existe"; 2ª (tras el IntegrityError): la real
        fake_q.filter_by.return_value.first.side_effect = [
            None, real_query.filter_by(value='198.51.100.20', ioc_type='ip').first()]
        with patch.object(IOC, 'query', fake_q):
            obj, created = IOC.get_or_create('198.51.100.20', 'ip')
        assert created is False
        assert obj.id == winner.id

    def test_savepoint_no_revierte_el_trabajo_pendiente_del_llamador(self, app, db_session):
        """El IntegrityError solo deshace el SAVEPOINT: lo anterior de la transacción sobrevive."""
        winner = IOC(value='198.51.100.30', ioc_type='ip')
        db_session.session.add(winner)
        db_session.session.commit()

        pendiente = IOC(value='198.51.100.31', ioc_type='ip')
        db_session.session.add(pendiente)
        db_session.session.flush()                      # trabajo previo del llamador, sin commit

        real_first = IOC.query.filter_by(value='198.51.100.30', ioc_type='ip').first()
        fake_q = MagicMock()
        fake_q.filter_by.return_value.first.side_effect = [None, real_first]
        with patch.object(IOC, 'query', fake_q):
            IOC.get_or_create('198.51.100.30', 'ip')
        db_session.session.commit()

        assert IOC.query.filter_by(value='198.51.100.31', ioc_type='ip').count() == 1

    def test_error_que_no_es_el_conflicto_no_se_oculta(self, app, db_session):
        """Si el IntegrityError no es por (value, ioc_type) debe propagarse, no tragarse."""
        fake_q = MagicMock()
        fake_q.filter_by.return_value.first.return_value = None     # nunca "existe"
        with patch.object(IOC, 'query', fake_q), \
             patch.object(db_session.session, 'flush',
                          side_effect=IntegrityError('stmt', {}, Exception('otra restriccion'))):
            with pytest.raises(IntegrityError):
                IOC.get_or_create('198.51.100.40', 'ip')
        db_session.session.rollback()


class TestBorradoDeUsuario:
    def test_borrar_usuario_conserva_el_analisis_con_user_id_null(self, app, db_session):
        user = User(username='mig_borrable', email='borrable@soc-test.local', role='analyst', is_active=True)
        user.set_password('Passw0rd!Test1')
        ioc = IOC(value='198.51.100.50', ioc_type='ip')
        db_session.session.add_all([user, ioc])
        db_session.session.commit()
        analysis = IOCAnalysis(ioc_id=ioc.id, user_id=user.id, confidence_score=10, risk_level='BAJO')
        db_session.session.add(analysis)
        db_session.session.commit()
        aid, uid = analysis.id, user.id
        db_session.session.expire_all()

        # DELETE directo en SQL: ejercita la FK de la BD, no el cascade del ORM
        db_session.session.execute(text('delete from users where id=:i'), {'i': uid})
        db_session.session.commit()

        row = db_session.session.execute(
            text('select user_id from ioc_analyses where id=:i'), {'i': aid}).fetchone()
        assert row is not None and row[0] is None       # sobrevive, huérfano

    def test_fk_declarada_con_set_null_en_postgres(self, app, db_session):
        d = db_session.session.execute(text(
            "select pg_get_constraintdef(oid) from pg_constraint "
            "where conname='ioc_analyses_user_id_fkey'")).scalar()
        assert 'ON DELETE SET NULL' in d
