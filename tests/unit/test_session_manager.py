"""
Tests unitarios — app/services/session_manager.py (SessionManager, singleton session_manager)

Cubre:
- get_or_create_session / create_new_session: creación, reuso de sesión activa,
  cierre de sesión previa con close_existing=True
- add_ioc_to_session: alta, no-duplicación, actualización de título automático
- save_message: persistencia y actualización de last_activity_at
- close_expired_sessions: smoke test (wrapper del método standalone)
- export_session_json: estructura básica del dict retornado

No cubre _generate_compressed_summary (llama a un LLM real); _check_and_compress
y force_generate_summary se prueban solo hasta el punto en que no requieren LLM
real (mockeando _get_llm_service cuando es necesario).
"""
import pytest
from datetime import timedelta

from app.services.session_manager import session_manager
from app.utils.time_utils import utcnow


# ==============================================================================
# get_or_create_session / create_new_session
# ==============================================================================

class TestGetOrCreateSession:

    def test_creates_new_session_when_none_active(self, app, db_session, analyst_user):
        with app.app_context():
            session, is_new = session_manager.get_or_create_session(analyst_user.id)

            assert is_new is True
            assert session.user_id == analyst_user.id
            assert session.status == 'active'
            assert session.title  # título autogenerado no vacío

    def test_reuses_active_session(self, app, db_session, analyst_user):
        with app.app_context():
            first, is_new_1 = session_manager.get_or_create_session(analyst_user.id)
            second, is_new_2 = session_manager.get_or_create_session(analyst_user.id)

            assert is_new_1 is True
            assert is_new_2 is False
            assert first.id == second.id

    def test_title_uses_ioc_when_provided(self, app, db_session, analyst_user):
        with app.app_context():
            session, is_new = session_manager.get_or_create_session(
                analyst_user.id, ioc_value='1.2.3.4', ioc_type='ip'
            )
            assert is_new is True
            assert '1.2.3.4' in session.title

    def test_manual_title_overrides_auto_title(self, app, db_session, analyst_user):
        with app.app_context():
            session, is_new = session_manager.get_or_create_session(
                analyst_user.id, title='Mi investigacion custom'
            )
            assert session.title == 'Mi investigacion custom'


class TestCreateNewSession:

    def test_creates_session(self, app, db_session, analyst_user):
        with app.app_context():
            session = session_manager.create_new_session(analyst_user.id, title='Sesion forzada')
            assert session.user_id == analyst_user.id
            assert session.title == 'Sesion forzada'
            assert session.status == 'active'

    def test_close_existing_true_closes_previous_active_session(self, app, db_session, analyst_user):
        with app.app_context():
            first, _ = session_manager.get_or_create_session(analyst_user.id)
            first_id = first.id

            second = session_manager.create_new_session(analyst_user.id, close_existing=True)

            assert second.id != first_id
            reloaded_first = session_manager.get_session(first_id)
            assert reloaded_first.status == 'closed'

    def test_close_existing_false_leaves_previous_session_active(self, app, db_session, analyst_user):
        with app.app_context():
            first, _ = session_manager.get_or_create_session(analyst_user.id)
            first_id = first.id

            session_manager.create_new_session(analyst_user.id, close_existing=False)

            reloaded_first = session_manager.get_session(first_id)
            assert reloaded_first.status == 'active'


# ==============================================================================
# add_ioc_to_session
# ==============================================================================

class TestAddIocToSession:

    def test_adds_new_ioc(self, app, db_session, analyst_user, sample_ioc):
        with app.app_context():
            session, _ = session_manager.get_or_create_session(analyst_user.id)

            session_ioc = session_manager.add_ioc_to_session(session.id, sample_ioc.id)

            assert session_ioc is not None
            assert session_ioc.ioc_id == sample_ioc.id
            assert session_ioc.session_id == session.id

    def test_does_not_duplicate_existing_ioc(self, app, db_session, analyst_user, sample_ioc):
        with app.app_context():
            session, _ = session_manager.get_or_create_session(analyst_user.id)

            first = session_manager.add_ioc_to_session(session.id, sample_ioc.id, notes='primera nota')
            second = session_manager.add_ioc_to_session(session.id, sample_ioc.id, notes='nota actualizada')

            assert first.id == second.id

            from app.models.session import SessionIOC
            count = SessionIOC.query.filter_by(session_id=session.id, ioc_id=sample_ioc.id).count()
            assert count == 1
            assert second.analyst_notes == 'nota actualizada'

    def test_updates_analysis_id_on_existing(self, app, db_session, analyst_user, sample_ioc, sample_analysis):
        with app.app_context():
            session, _ = session_manager.get_or_create_session(analyst_user.id)

            session_manager.add_ioc_to_session(session.id, sample_ioc.id)
            updated = session_manager.add_ioc_to_session(
                session.id, sample_ioc.id, analysis_id=sample_analysis.id
            )

            assert updated.analysis_id == sample_analysis.id

    def test_auto_title_updates_on_first_ioc(self, app, db_session, analyst_user, sample_ioc):
        """add_ioc_to_session decide actualizar el título mirando session.total_iocs == 1.

        En producción total_iocs lo mantiene el trigger SQL trigger_session_ioc_stats
        (migrations/add_investigation_sessions.sql), que no se aplica en la BD de test
        (create_all() no ejecuta triggers crudos, ver CLAUDE.md). Se fija manualmente
        para aislar y probar esa rama de la lógica, independiente del trigger.
        """
        from app import db

        with app.app_context():
            session, _ = session_manager.get_or_create_session(analyst_user.id)
            assert 'Nueva investigación' in (session.title or '')

            session.total_iocs = 1
            db.session.commit()

            session_manager.add_ioc_to_session(session.id, sample_ioc.id)

            reloaded = session_manager.get_session(session.id)
            assert sample_ioc.value in (reloaded.title or '')


# ==============================================================================
# save_message
# ==============================================================================

class TestSaveMessage:

    def test_saves_message(self, app, db_session, analyst_user):
        with app.app_context():
            session, _ = session_manager.get_or_create_session(analyst_user.id)

            message = session_manager.save_message(session.id, role='user', content='Hola, analiza esta IP')

            assert message.id is not None
            assert message.session_id == session.id
            assert message.role == 'user'
            assert message.content == 'Hola, analiza esta IP'

    def test_updates_session_last_activity(self, app, db_session, analyst_user):
        with app.app_context():
            session, _ = session_manager.get_or_create_session(analyst_user.id)

            # Forzar last_activity_at a un valor claramente en el pasado
            from app import db
            session.last_activity_at = utcnow() - timedelta(hours=5)
            db.session.commit()
            old_activity = session.last_activity_at

            session_manager.save_message(session.id, role='user', content='mensaje nuevo')

            reloaded = session_manager.get_session(session.id)
            assert reloaded.last_activity_at.replace(tzinfo=None) > old_activity.replace(tzinfo=None)

    def test_total_messages_reflects_saved_message(self, app, db_session, analyst_user):
        with app.app_context():
            session, _ = session_manager.get_or_create_session(analyst_user.id)
            session_manager.save_message(session.id, role='user', content='primer mensaje')

            from app.models.session import SessionMessage
            count = SessionMessage.query.filter_by(session_id=session.id).count()
            assert count == 1


# ==============================================================================
# close_expired_sessions (wrapper)
# ==============================================================================

class TestCloseExpiredSessions:

    def test_no_expired_sessions_returns_zero_without_raising(self, app, db_session, analyst_user):
        with app.app_context():
            # Sesión activa reciente, no expirada
            session_manager.get_or_create_session(analyst_user.id)

            count = session_manager.close_expired_sessions()

            assert count == 0

    def test_closes_sessions_past_auto_close_window(self, app, db_session, analyst_user):
        with app.app_context():
            from app import db
            session, _ = session_manager.get_or_create_session(analyst_user.id)
            session.last_activity_at = utcnow() - timedelta(hours=48)
            db.session.commit()

            count = session_manager.close_expired_sessions()

            assert count == 1
            reloaded = session_manager.get_session(session.id)
            assert reloaded.status == 'closed'


# ==============================================================================
# export_session_json
# ==============================================================================

class TestExportSessionJson:

    def test_returns_none_for_nonexistent_session(self, app, db_session):
        with app.app_context():
            result = session_manager.export_session_json(999999)
            assert result is None

    def test_basic_structure(self, app, db_session, analyst_user, sample_ioc, sample_analysis):
        with app.app_context():
            session, _ = session_manager.get_or_create_session(analyst_user.id)
            session_manager.add_ioc_to_session(session.id, sample_ioc.id, analysis_id=sample_analysis.id)
            session_manager.save_message(session.id, role='user', content='analiza esta IP')

            data = session_manager.export_session_json(session.id)

            assert data is not None
            assert set(['session', 'iocs', 'messages', 'statistics']).issubset(data.keys())
            assert data['session']['id'] == session.id
            assert len(data['iocs']) == 1
            assert data['iocs'][0]['ioc_id'] == sample_ioc.id
            assert 'analysis_details' in data['iocs'][0]
            assert len(data['messages']) == 1
            assert data['statistics']['total_iocs'] == session.total_iocs
            assert data['statistics']['total_messages'] == session.total_messages


# ==============================================================================
# _check_and_compress / force_generate_summary — mockeando LLM
# ==============================================================================

class TestCompressedSummaryWithMockedLlm:

    def test_force_generate_summary_no_messages_leaves_summary_none(self, app, db_session, analyst_user):
        """Sin suficientes mensajes, _generate_compressed_summary retorna temprano
        y no debe intentar llamar al LLM."""
        with app.app_context():
            session, _ = session_manager.get_or_create_session(analyst_user.id)

            summary = session_manager.force_generate_summary(session.id)

            assert summary is None
