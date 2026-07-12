"""
Tests de Modelos — T3A-05
Cubre: User, IOC, IOCAnalysis, Incident, generate_ticket_id thread-safe, to_dict
"""
import pytest
from app.utils.time_utils import utcnow


# ==============================================================================
# USER
# ==============================================================================

class TestUserModel:

    def test_user_creation(self, db_session, app):
        """Crear usuario con campos mínimos."""
        from app.models.ioc import User
        with app.app_context():
            user = User(username='modeluser', email='model@test.local', role='analyst')
            user.set_password('Pass123!')
            db_session.session.add(user)
            db_session.session.commit()
            assert user.id is not None

    def test_uuid_auto_generated(self, db_session, analyst_user, app):
        """UUID se genera automáticamente al crear usuario."""
        with app.app_context():
            assert analyst_user.uuid is not None
            assert str(analyst_user.uuid) != ''

    def test_set_password_hashes(self, db_session, app):
        """set_password almacena hash, no texto plano."""
        from app.models.ioc import User
        with app.app_context():
            user = User(username='hashtest', email='hash@test.local')
            user.set_password('MySecretPass!')
            assert user.password_hash != 'MySecretPass!'
            assert len(user.password_hash) > 20

    def test_check_password_correct(self, db_session, analyst_user, app):
        """check_password devuelve True con contraseña correcta."""
        with app.app_context():
            assert analyst_user.check_password('AnalystPass123!') is True

    def test_check_password_wrong(self, db_session, analyst_user, app):
        """check_password devuelve False con contraseña incorrecta."""
        with app.app_context():
            assert analyst_user.check_password('WrongPassword!') is False

    def test_check_password_empty(self, db_session, analyst_user, app):
        """check_password devuelve False con contraseña vacía."""
        with app.app_context():
            assert analyst_user.check_password('') is False

    def test_to_dict_fields(self, db_session, analyst_user, app):
        """to_dict incluye todos los campos esperados."""
        with app.app_context():
            d = analyst_user.to_dict()
            assert 'id' in d
            assert 'uuid' in d
            assert 'username' in d
            assert 'email' in d
            assert 'role' in d
            assert 'is_active' in d
            assert 'created_at' in d

    def test_to_dict_no_password_hash(self, db_session, analyst_user, app):
        """to_dict NO expone password_hash."""
        with app.app_context():
            d = analyst_user.to_dict()
            assert 'password_hash' not in d
            assert 'password' not in d

    def test_to_dict_role_analyst(self, db_session, analyst_user, app):
        with app.app_context():
            assert analyst_user.to_dict()['role'] == 'analyst'

    def test_to_dict_role_admin(self, db_session, admin_user, app):
        with app.app_context():
            assert admin_user.to_dict()['role'] == 'admin'

    def test_default_is_active_true(self, db_session, app):
        """Por defecto, is_active=True."""
        from app.models.ioc import User
        with app.app_context():
            user = User(username='activedefault', email='active@test.local')
            user.set_password('Pass123!')
            db_session.session.add(user)
            db_session.session.commit()
            assert user.is_active is True

    def test_username_unique(self, db_session, analyst_user, app):
        """Insertar usuario con username duplicado lanza IntegrityError."""
        from app.models.ioc import User
        from sqlalchemy.exc import IntegrityError
        with app.app_context():
            dup = User(username='test_analyst', email='other@test.local')
            dup.set_password('Pass123!')
            db_session.session.add(dup)
            with pytest.raises(IntegrityError):
                db_session.session.commit()

    def test_email_unique(self, db_session, analyst_user, app):
        """Insertar usuario con email duplicado lanza IntegrityError."""
        from app.models.ioc import User
        from sqlalchemy.exc import IntegrityError
        with app.app_context():
            dup = User(username='otheruser', email='analyst@soc-test.local')
            dup.set_password('Pass123!')
            db_session.session.add(dup)
            with pytest.raises(IntegrityError):
                db_session.session.commit()

    def test_repr(self, db_session, analyst_user, app):
        with app.app_context():
            assert 'test_analyst' in repr(analyst_user)


# ==============================================================================
# IOC
# ==============================================================================

class TestIOCModel:

    def test_ioc_creation(self, db_session, sample_ioc, app):
        """IOC se crea correctamente con campos básicos."""
        with app.app_context():
            assert sample_ioc.id is not None
            assert sample_ioc.value == '185.220.101.34'
            assert sample_ioc.ioc_type == 'ip'

    def test_ioc_uuid_auto_generated(self, db_session, sample_ioc, app):
        with app.app_context():
            assert sample_ioc.uuid is not None

    def test_ioc_to_dict_fields(self, db_session, sample_ioc, app):
        with app.app_context():
            d = sample_ioc.to_dict()
            assert 'id' in d
            assert 'uuid' in d
            assert 'value' in d
            assert 'type' in d
            assert 'first_seen' in d
            assert 'times_analyzed' in d
            assert 'is_whitelisted' in d
            assert 'tags' in d

    def test_ioc_to_dict_latest_risk(self, db_session, sample_analysis, app):
        """to_dict incluye latest_risk_level de la última análisis."""
        with app.app_context():
            d = sample_analysis.ioc.to_dict()
            assert d['latest_risk_level'] == 'ALTO'

    def test_ioc_whitelisted_default_false(self, db_session, sample_ioc, app):
        with app.app_context():
            assert sample_ioc.is_whitelisted is False

    def test_ioc_tags_list(self, db_session, sample_ioc, app):
        with app.app_context():
            assert isinstance(sample_ioc.tags, list)
            assert 'malicious' in sample_ioc.tags

    def test_ioc_repr(self, db_session, sample_ioc, app):
        with app.app_context():
            assert 'ip' in repr(sample_ioc)

    def test_ioc_domain_creation(self, db_session, app):
        """Crear IOC de tipo dominio."""
        from app.models.ioc import IOC
        with app.app_context():
            ioc = IOC(value='malware.evil.com', ioc_type='domain')
            db_session.session.add(ioc)
            db_session.session.commit()
            assert ioc.id is not None
            assert ioc.ioc_type == 'domain'

    def test_ioc_hash_creation(self, db_session, app):
        """Crear IOC de tipo hash."""
        from app.models.ioc import IOC
        with app.app_context():
            sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
            ioc = IOC(value=sha256, ioc_type='hash')
            db_session.session.add(ioc)
            db_session.session.commit()
            assert ioc.ioc_type == 'hash'


# ==============================================================================
# IOCANALYSIS
# ==============================================================================

class TestIOCAnalysisModel:

    def test_analysis_creation(self, db_session, sample_analysis, app):
        """IOCAnalysis se crea con campos básicos."""
        with app.app_context():
            assert sample_analysis.id is not None
            assert sample_analysis.confidence_score == 82
            assert sample_analysis.risk_level == 'ALTO'

    def test_analysis_to_dict_basic(self, db_session, sample_analysis, app):
        """to_dict sin include_details tiene campos básicos."""
        with app.app_context():
            d = sample_analysis.to_dict(include_details=False)
            assert 'id' in d
            assert 'confidence_score' in d
            assert 'risk_level' in d
            assert 'recommendation' in d
            assert 'ioc_value' in d
            assert 'ioc_type' in d
            # No debe tener datos de APIs
            assert 'virustotal' not in d

    def test_analysis_to_dict_with_details(self, db_session, sample_analysis, app):
        """to_dict con include_details=True incluye datos de APIs."""
        with app.app_context():
            d = sample_analysis.to_dict(include_details=True)
            assert 'virustotal' in d
            assert 'abuseipdb' in d
            assert 'mitre_techniques' in d

    def test_analysis_sources_used(self, db_session, sample_analysis, app):
        with app.app_context():
            assert 'virustotal' in sample_analysis.sources_used
            assert 'abuseipdb' in sample_analysis.sources_used

    def test_analysis_to_dict_analyst_name(self, db_session, sample_analysis, analyst_user, app):
        """to_dict incluye nombre del analista, no ID."""
        with app.app_context():
            d = sample_analysis.to_dict()
            assert d['analyst'] == 'test_analyst'

    def test_analysis_repr(self, db_session, sample_analysis, app):
        with app.app_context():
            assert 'ALTO' in repr(sample_analysis)


# ==============================================================================
# INCIDENT
# ==============================================================================

class TestIncidentModel:

    def test_incident_creation(self, db_session, sample_incident, app):
        """Incident se crea correctamente."""
        with app.app_context():
            assert sample_incident.id is not None
            assert sample_incident.ticket_id == 'SOC-TEST-001'
            assert sample_incident.status == 'open'

    def test_incident_uuid_auto(self, db_session, sample_incident, app):
        with app.app_context():
            assert sample_incident.uuid is not None

    def test_generate_ticket_id_format(self, db_session, app):
        """generate_ticket_id produce formato SOC-YYYYMMDD-NNN."""
        with app.app_context():
            ticket = __import__('app.models.ioc', fromlist=['Incident']).Incident.generate_ticket_id()
            today = utcnow().strftime('%Y%m%d')
            assert ticket.startswith(f'SOC-{today}-')
            parts = ticket.split('-')
            assert len(parts) == 3
            assert parts[2].isdigit()

    def test_generate_ticket_id_sequential(self, db_session, app):
        """Dos tickets generados en el mismo día son distintos."""
        from app.models.ioc import Incident
        with app.app_context():
            t1 = Incident.generate_ticket_id()
            inc = Incident(ticket_id=t1, title='Inc 1', severity='P3',
                           status='open', created_by=None)
            db_session.session.add(inc)
            db_session.session.commit()
            t2 = Incident.generate_ticket_id()
            assert t1 != t2

    def test_add_timeline_event(self, db_session, sample_incident, app):
        """add_timeline_event agrega evento correctamente."""
        from app.models.ioc import Incident
        initial_len = len(sample_incident.timeline or [])
        sample_incident.add_timeline_event('finding', 'Se detectó actividad C2.', user='test_analyst')
        db_session.session.commit()
        # Re-fetch para evitar problemas de identidad entre sesiones SQLAlchemy
        refreshed = db_session.session.get(Incident, sample_incident.id)
        assert len(refreshed.timeline) == initial_len + 1
        last = refreshed.timeline[-1]
        assert last['type'] == 'finding'
        assert last['description'] == 'Se detectó actividad C2.'
        assert last['user'] == 'test_analyst'
        assert 'timestamp' in last

    def test_timeline_is_append_only(self, db_session, sample_incident, app):
        """Cada add_timeline_event preserva eventos previos."""
        from app.models.ioc import Incident
        sample_incident.add_timeline_event('created', 'Incidente creado')
        sample_incident.add_timeline_event('updated', 'Título actualizado')
        db_session.session.commit()
        refreshed = db_session.session.get(Incident, sample_incident.id)
        types = [e['type'] for e in refreshed.timeline]
        assert 'created' in types
        assert 'updated' in types

    def test_to_dict_fields(self, db_session, sample_incident, app):
        """to_dict incluye campos principales."""
        with app.app_context():
            d = sample_incident.to_dict()
            assert 'id' in d
            assert 'ticket_id' in d
            assert 'title' in d
            assert 'severity' in d
            assert 'status' in d
            assert 'created_at' in d
            assert 'timeline' in d

    def test_to_dict_include_iocs_false(self, db_session, sample_incident, app):
        """Sin include_iocs, no hay linked_iocs en el dict."""
        with app.app_context():
            d = sample_incident.to_dict(include_iocs=False)
            assert 'linked_iocs' not in d

    def test_to_dict_include_iocs_true(self, db_session, sample_incident, app):
        """Con include_iocs=True, tiene linked_iocs."""
        with app.app_context():
            d = sample_incident.to_dict(include_iocs=True)
            assert 'linked_iocs' in d
            assert isinstance(d['linked_iocs'], list)

    def test_incident_repr(self, db_session, sample_incident, app):
        with app.app_context():
            assert 'SOC-TEST-001' in repr(sample_incident)

    def test_default_status_open(self, db_session, analyst_user, app):
        """Incident por defecto tiene status='open'."""
        from app.models.ioc import Incident
        with app.app_context():
            inc = Incident(
                ticket_id='SOC-TEST-STATUS',
                title='Test Status',
                created_by=analyst_user.id
            )
            db_session.session.add(inc)
            db_session.session.commit()
            assert inc.status == 'open'
