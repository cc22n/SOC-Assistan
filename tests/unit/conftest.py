"""
SOC Agent - Test Fixtures para Tests Unitarios
Fase 3 — Sprint 3A

Estructura:
  app          → Flask app con TestingConfig (scope=session)
  db_session   → DB limpia por test via TRUNCATE CASCADE (scope=function)
  client       → Flask test client sin autenticar
  admin_user   → Objeto User con role='admin'
  analyst_user → Objeto User con role='analyst'
  other_user   → Segundo usuario analista (para tests de IDOR)
  admin_client → Client autenticado como admin
  analyst_client → Client autenticado como analista
  other_client   → Client autenticado como other_user (IDOR)
  sample_ioc   → Objeto IOC de prueba (IP maliciosa)
  sample_analysis → IOCAnalysis asociada a sample_ioc + analyst_user
  sample_incident → Incident creado por analyst_user
"""
import pytest
import os
from sqlalchemy import text

# ==============================================================================
# CONFIGURAR ENTORNO ANTES DE IMPORTAR LA APP
# ==============================================================================
os.environ['FLASK_ENV'] = 'testing'
os.environ['SECRET_KEY'] = 'test-secret-key-for-pytest-not-for-production-use'
os.environ['DATABASE_URL'] = os.environ.get(
    'TEST_DATABASE_URL',
    'postgresql://soc_admin:1234@127.0.0.1:5432/soc_agent_test?client_encoding=utf8'
)

# ==============================================================================
# APP
# ==============================================================================

@pytest.fixture(scope='session')
def app():
    """Flask app configurada para testing con PostgreSQL."""
    from app import create_app

    application = create_app('testing')
    application.config.update({
        'TESTING': True,
        'WTF_CSRF_ENABLED': False,
        'SERVER_NAME': 'localhost',
        'PREFERRED_URL_SCHEME': 'http',
        # Rate limiter: desactivar completamente en tests
        'RATELIMIT_ENABLED': False,
        'RATELIMIT_STORAGE_URI': 'memory://',
        'SQLALCHEMY_DATABASE_URI': os.environ['DATABASE_URL'],
        'API_KEYS': {k: 'fake-test-key' for k in [
            'virustotal', 'abuseipdb', 'shodan', 'otx', 'greynoise',
            'google_safebrowsing', 'securitytrails', 'hybrid_analysis',
            'criminal_ip', 'pulsedive', 'urlscan', 'censys', 'ipinfo',
            'abusech_auth', 'xai', 'openai', 'groq', 'gemini',
            'anthropic', 'ipgeolocation',
        ]},
    })
    yield application


# ==============================================================================
# BASE DE DATOS
# ==============================================================================

@pytest.fixture(scope='function')
def db_session(app):
    """DB limpia por test. Crea tablas si no existen y hace TRUNCATE CASCADE al final."""
    from app import db

    with app.app_context():
        db.create_all()
        yield db

        db.session.rollback()
        table_names = [t.name for t in db.metadata.tables.values()]
        if table_names:
            db.session.execute(text(f"TRUNCATE TABLE {', '.join(table_names)} CASCADE;"))
            db.session.commit()
        db.session.remove()


# ==============================================================================
# CLIENTE HTTP
# ==============================================================================

@pytest.fixture(scope='function')
def client(app, db_session):
    """Flask test client sin autenticar."""
    with app.test_client() as c:
        yield c


# ==============================================================================
# USUARIOS
# ==============================================================================

@pytest.fixture(scope='function')
def admin_user(app, db_session):
    """Usuario con role='admin' persistido en la DB."""
    from app.models.ioc import User

    user = User(
        username='test_admin',
        email='admin@soc-test.local',
        role='admin',
        is_active=True,
    )
    user.set_password('AdminPass123!')
    db_session.session.add(user)
    db_session.session.commit()
    db_session.session.refresh(user)
    return user


@pytest.fixture(scope='function')
def analyst_user(app, db_session):
    """Usuario con role='analyst' persistido en la DB."""
    from app.models.ioc import User

    user = User(
        username='test_analyst',
        email='analyst@soc-test.local',
        role='analyst',
        is_active=True,
    )
    user.set_password('AnalystPass123!')
    db_session.session.add(user)
    db_session.session.commit()
    db_session.session.refresh(user)
    return user


@pytest.fixture(scope='function')
def other_user(app, db_session):
    """Segundo analista — usado para verificar aislamiento de recursos (IDOR)."""
    from app.models.ioc import User

    user = User(
        username='other_analyst',
        email='other@soc-test.local',
        role='analyst',
        is_active=True,
    )
    user.set_password('OtherPass123!')
    db_session.session.add(user)
    db_session.session.commit()
    db_session.session.refresh(user)
    return user


# ==============================================================================
# CLIENTES AUTENTICADOS
# ==============================================================================

def _authenticated_client(app, user):
    """
    Devuelve un test client con la sesión de Flask-Login ya establecida.
    Inyecta _user_id directamente en la cookie de sesión, evitando el
    flujo HTTP de login (que puede fallar por rate limits o config de CSRF).
    """
    c = app.test_client()
    with c.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True
    return c


@pytest.fixture(scope='function')
def admin_client(app, db_session, admin_user):
    """Test client autenticado como admin."""
    with _authenticated_client(app, admin_user) as c:
        yield c


@pytest.fixture(scope='function')
def analyst_client(app, db_session, analyst_user):
    """Test client autenticado como analyst."""
    with _authenticated_client(app, analyst_user) as c:
        yield c


@pytest.fixture(scope='function')
def other_client(app, db_session, other_user):
    """Test client autenticado como other_user — para tests de IDOR."""
    with _authenticated_client(app, other_user) as c:
        yield c


# ==============================================================================
# IOC Y ANÁLISIS DE EJEMPLO
# ==============================================================================

@pytest.fixture(scope='function')
def sample_ioc(app, db_session):
    """IOC de prueba: IP maliciosa conocida."""
    from app.models.ioc import IOC

    ioc = IOC(
        value='185.220.101.34',
        ioc_type='ip',
        is_whitelisted=False,
        tags=['tor', 'malicious'],
        meta_data={'source': 'test'},
    )
    db_session.session.add(ioc)
    db_session.session.commit()
    db_session.session.refresh(ioc)
    return ioc


@pytest.fixture(scope='function')
def sample_analysis(app, db_session, sample_ioc, analyst_user):
    """IOCAnalysis vinculada a sample_ioc y analyst_user con datos mínimos."""
    from app.models.ioc import IOCAnalysis

    analysis = IOCAnalysis(
        ioc_id=sample_ioc.id,
        user_id=analyst_user.id,
        confidence_score=82,
        risk_level='ALTO',
        recommendation='Bloquear en firewall perimetral.',
        sources_used=['virustotal', 'abuseipdb'],
        virustotal_data={'malicious': 47, 'suspicious': 3},
        abuseipdb_data={'abuse_confidence': 85, 'total_reports': 2847},
        processing_time=2.34,
    )
    db_session.session.add(analysis)
    db_session.session.commit()
    db_session.session.refresh(analysis)
    return analysis


# ==============================================================================
# INCIDENTE DE EJEMPLO
# ==============================================================================

@pytest.fixture(scope='function')
def sample_incident(app, db_session, analyst_user):
    """Incident creado por analyst_user con ticket_id fijo para tests."""
    from app.models.ioc import Incident

    incident = Incident(
        ticket_id='SOC-TEST-001',
        title='Test Incident — Actividad sospechosa en red',
        description='Detección de tráfico hacia IP conocida como C2.',
        severity='P2',
        status='open',
        created_by=analyst_user.id,
    )
    db_session.session.add(incident)
    db_session.session.commit()
    db_session.session.refresh(incident)
    return incident


# ==============================================================================
# DATOS DE EJEMPLO (sin DB)
# ==============================================================================

@pytest.fixture
def malicious_ip():
    return '185.220.101.34'


@pytest.fixture
def clean_ip():
    return '8.8.8.8'


@pytest.fixture
def sample_domain():
    return 'malware-c2.evil.com'


@pytest.fixture
def sample_hash():
    return 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'


@pytest.fixture
def sample_url():
    return 'http://malware-c2.evil.com/payload.exe'


# ==============================================================================
# MOCK API RESPONSES
# ==============================================================================

@pytest.fixture
def mock_vt_malicious():
    """Respuesta VirusTotal para IP maliciosa."""
    return {
        'malicious': 47,
        'suspicious': 3,
        'harmless': 40,
        'undetected': 4,
        'asn': 13335,
        'as_owner': 'Hetzner',
        'country': 'DE',
        'reputation': -50,
    }


@pytest.fixture
def mock_vt_clean():
    """Respuesta VirusTotal para IP limpia."""
    return {
        'malicious': 0,
        'suspicious': 0,
        'harmless': 90,
        'undetected': 4,
        'asn': 15169,
        'as_owner': 'Google LLC',
        'country': 'US',
        'reputation': 50,
    }


@pytest.fixture
def mock_abuseipdb_malicious():
    return {
        'abuse_confidence': 85,
        'country': 'RU',
        'isp': 'Evil Hosting',
        'total_reports': 2847,
        'is_whitelisted': False,
    }


@pytest.fixture
def mock_api_error():
    return {'error': 'API key inválida o límite excedido'}
