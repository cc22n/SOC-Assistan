"""
Modelos de base de datos para IOCs y análisis
Optimizado para PostgreSQL
SOC Agent v3.1 - Febrero 2026

CAMBIOS v3.1:
- Agregados campos: censys_data, ipinfo_data (APIs v3.1)

CAMBIOS v3:
- Agregados campos para TODAS las APIs de threat intelligence
- Nuevos campos: criminal_ip_data, pulsedive_data, urlscan_data, malwarebazaar_data
- Eliminados: ipqualityscore_data (API removida)
"""
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.dialects.postgresql import JSON, JSONB, UUID
from app import db
import uuid


class User(UserMixin, db.Model):
    """Modelo de usuario"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(UUID(as_uuid=True), unique=True, default=uuid.uuid4, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='analyst', index=True)  # analyst, admin, viewer
    is_active = db.Column(db.Boolean, default=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime)

    # Relaciones
    analyses = db.relationship('IOCAnalysis', backref='analyst', lazy='dynamic',
                               cascade='all, delete-orphan')
    created_incidents = db.relationship('Incident', backref='creator',
                                        foreign_keys='Incident.created_by',
                                        lazy='dynamic')
    assigned_incidents = db.relationship('Incident', backref='assignee',
                                         foreign_keys='Incident.assigned_to',
                                         lazy='dynamic')

    def set_password(self, password):
        """Hashea y guarda la contraseña"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verifica la contraseña"""
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'uuid': str(self.uuid),
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

    def __repr__(self):
        return f'<User {self.username}>'


class IOC(db.Model):
    """Modelo de Indicator of Compromise"""
    __tablename__ = 'iocs'

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(UUID(as_uuid=True), unique=True, default=uuid.uuid4, nullable=False)
    value = db.Column(db.String(500), nullable=False)
    ioc_type = db.Column(db.String(20), nullable=False)  # ip, hash, domain, url
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    last_analyzed = db.Column(db.DateTime, default=datetime.utcnow,
                              onupdate=datetime.utcnow, index=True)
    times_analyzed = db.Column(db.Integer, default=1)
    is_whitelisted = db.Column(db.Boolean, default=False, index=True)
    whitelist_reason = db.Column(db.Text)

    # Tags y metadatos (PostgreSQL JSONB)
    tags = db.Column(JSONB, default=list)
    meta_data = db.Column(JSONB, default=dict)

    # Relaciones
    analyses = db.relationship('IOCAnalysis', backref='ioc', lazy='dynamic',
                               cascade='all, delete-orphan')

    # Índices compuestos para búsquedas rápidas
    __table_args__ = (
        db.Index('idx_ioc_value_type', 'value', 'ioc_type'),
        db.Index('idx_ioc_type_whitelisted', 'ioc_type', 'is_whitelisted'),
        db.Index('idx_ioc_last_analyzed', 'last_analyzed'),
        db.Index('idx_ioc_value_gin', 'value', postgresql_using='gin',
                 postgresql_ops={'value': 'gin_trgm_ops'}),
    )

    def to_dict(self):
        latest_analysis = self.analyses.order_by(IOCAnalysis.created_at.desc()).first()
        return {
            'id': self.id,
            'uuid': str(self.uuid),
            'value': self.value,
            'type': self.ioc_type,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_analyzed': self.last_analyzed.isoformat() if self.last_analyzed else None,
            'times_analyzed': self.times_analyzed,
            'is_whitelisted': self.is_whitelisted,
            'whitelist_reason': self.whitelist_reason,
            'tags': self.tags or [],
            'meta_data': self.meta_data or {},
            'latest_risk_level': latest_analysis.risk_level if latest_analysis else None,
            'latest_confidence': latest_analysis.confidence_score if latest_analysis else None
        }

    def __repr__(self):
        return f'<IOC {self.ioc_type}:{self.value[:20]}>'


class IOCAnalysis(db.Model):
    """
    Modelo de análisis de IOC

    v3.0 - Campos actualizados para todas las APIs
    """
    __tablename__ = 'ioc_analyses'

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(UUID(as_uuid=True), unique=True, default=uuid.uuid4, nullable=False)
    ioc_id = db.Column(db.Integer, db.ForeignKey('iocs.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    # Resultados del análisis
    confidence_score = db.Column(db.Integer, default=0, index=True)
    risk_level = db.Column(db.String(20), index=True)  # CRÍTICO, ALTO, MEDIO, BAJO, LIMPIO
    recommendation = db.Column(db.Text)

    # =========================================================================
    # Datos de APIs de Threat Intelligence (PostgreSQL JSONB)
    # =========================================================================

    # APIs Principales
    virustotal_data = db.Column(JSONB)
    abuseipdb_data = db.Column(JSONB)
    shodan_data = db.Column(JSONB)
    otx_data = db.Column(JSONB)
    greynoise_data = db.Column(JSONB)

    # APIs abuse.ch
    urlhaus_data = db.Column(JSONB)
    threatfox_data = db.Column(JSONB)
    malwarebazaar_data = db.Column(JSONB)  # NUEVO

    # Otras APIs
    google_safebrowsing_data = db.Column(JSONB)
    securitytrails_data = db.Column(JSONB)
    hybrid_analysis_data = db.Column(JSONB)

    # NUEVAS APIs v3
    criminal_ip_data = db.Column(JSONB)  # NUEVO
    pulsedive_data = db.Column(JSONB)  # NUEVO
    urlscan_data = db.Column(JSONB)  # NUEVO
    shodan_internetdb_data = db.Column(JSONB)  # NUEVO (gratis)
    ip_api_data = db.Column(JSONB)  # NUEVO (geolocalización gratis)

    # APIs v3.1
    censys_data = db.Column(JSONB)  # NUEVO v3.1 (Platform API v3)
    ipinfo_data = db.Column(JSONB)  # NUEVO v3.1 (Lite, geoloc + ASN)

    # =========================================================================
    # Análisis LLM y MITRE
    # =========================================================================
    llm_analysis = db.Column(JSONB)
    mitre_techniques = db.Column(JSONB, default=list)

    # =========================================================================
    # Metadata
    # =========================================================================
    sources_used = db.Column(JSONB, default=list)  # Lista de APIs consultadas
    errors = db.Column(JSONB, default=list)
    processing_time = db.Column(db.Float)  # en segundos
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Índices adicionales
    __table_args__ = (
        db.Index('idx_analysis_risk_level', 'risk_level', 'created_at'),
        db.Index('idx_analysis_confidence', 'confidence_score', 'created_at'),
        db.Index('idx_analysis_ioc_created', 'ioc_id', 'created_at'),
        db.Index('idx_virustotal_data', 'virustotal_data', postgresql_using='gin'),
        db.Index('idx_mitre_techniques', 'mitre_techniques', postgresql_using='gin'),
    )

    def to_dict(self, include_details=True):
        data = {
            'id': self.id,
            'uuid': str(self.uuid),
            'ioc_id': self.ioc_id,
            'ioc_value': self.ioc.value if self.ioc else None,
            'ioc_type': self.ioc.ioc_type if self.ioc else None,
            'confidence_score': self.confidence_score,
            'risk_level': self.risk_level,
            'recommendation': self.recommendation,
            'analyst': self.analyst.username if self.analyst else 'System',
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'processing_time': self.processing_time,
            'sources_used': self.sources_used or []
        }

        if include_details:
            data.update({
                # APIs Principales
                'virustotal': self.virustotal_data,
                'abuseipdb': self.abuseipdb_data,
                'shodan': self.shodan_data,
                'otx': self.otx_data,
                'greynoise': self.greynoise_data,

                # APIs abuse.ch
                'urlhaus': self.urlhaus_data,
                'threatfox': self.threatfox_data,
                'malwarebazaar': self.malwarebazaar_data,

                # Otras APIs
                'google_safebrowsing': self.google_safebrowsing_data,
                'securitytrails': self.securitytrails_data,
                'hybrid_analysis': self.hybrid_analysis_data,

                # Nuevas APIs v3
                'criminal_ip': self.criminal_ip_data,
                'pulsedive': self.pulsedive_data,
                'urlscan': self.urlscan_data,
                'shodan_internetdb': self.shodan_internetdb_data,
                'ip_api': self.ip_api_data,

                # APIs v3.1
                'censys': self.censys_data,
                'ipinfo': self.ipinfo_data,

                # LLM y MITRE
                'llm_analysis': self.llm_analysis,
                'mitre_techniques': self.mitre_techniques,
                'errors': self.errors
            })

        return data

    def __repr__(self):
        return f'<Analysis {self.id} - {self.risk_level}>'


class IncidentIOC(db.Model):
    """Tabla pivot: multiples IOCs vinculados a un incidente"""
    __tablename__ = 'incident_iocs'

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.id', ondelete='CASCADE'), nullable=False)
    ioc_id = db.Column(db.Integer, db.ForeignKey('iocs.id', ondelete='CASCADE'), nullable=False)
    analysis_id = db.Column(db.Integer, db.ForeignKey('ioc_analyses.id', ondelete='SET NULL'))

    role = db.Column(db.String(20), default='related')  # primary, related, context
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)

    # Relaciones
    ioc = db.relationship('IOC', backref='incident_links')
    analysis = db.relationship('IOCAnalysis')

    __table_args__ = (
        db.UniqueConstraint('incident_id', 'ioc_id', name='unique_incident_ioc'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'ioc_id': self.ioc_id,
            'ioc_value': self.ioc.value if self.ioc else None,
            'ioc_type': self.ioc.ioc_type if self.ioc else None,
            'role': self.role,
            'risk_level': self.analysis.risk_level if self.analysis else None,
            'confidence_score': self.analysis.confidence_score if self.analysis else None,
            'added_at': self.added_at.isoformat() if self.added_at else None,
            'notes': self.notes
        }


class Incident(db.Model):
    """Modelo de incidente de seguridad"""
    __tablename__ = 'incidents'

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(UUID(as_uuid=True), unique=True, default=uuid.uuid4, nullable=False)
    ticket_id = db.Column(db.String(50), unique=True, nullable=False, index=True)

    # Información del incidente
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(10), index=True)  # P1, P2, P3, P4
    status = db.Column(db.String(20), default='open', index=True)

    # Relaciones
    analysis_id = db.Column(db.Integer, db.ForeignKey('ioc_analyses.id'))
    analysis = db.relationship('IOCAnalysis', backref='incidents')

    session_id = db.Column(db.Integer, db.ForeignKey('investigation_sessions.id', ondelete='SET NULL'))
    session = db.relationship('InvestigationSession', foreign_keys=[session_id])

    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, index=True)
    resolved_at = db.Column(db.DateTime)

    # Notas y seguimiento
    notes = db.Column(db.Text)
    timeline = db.Column(JSONB, default=list)
    related_iocs = db.Column(JSONB, default=list)

    # Relacion con IOCs (tabla pivot)
    linked_iocs = db.relationship('IncidentIOC', backref='incident', cascade='all, delete-orphan',
                                  lazy='dynamic')

    __table_args__ = (
        db.Index('idx_incident_status_severity', 'status', 'severity'),
        db.Index('idx_incident_created', 'created_at'),
    )

    @staticmethod
    def generate_ticket_id():
        """Genera un ticket_id unico tipo SOC-20260220-001"""
        today = datetime.utcnow().strftime('%Y%m%d')
        count = Incident.query.filter(
            Incident.ticket_id.like(f'SOC-{today}-%')
        ).count()
        return f"SOC-{today}-{count + 1:03d}"

    def add_timeline_event(self, event_type, description, user=None):
        """Agrega evento al timeline"""
        if self.timeline is None:
            self.timeline = []
        self.timeline = self.timeline + [{
            'type': event_type,
            'description': description,
            'user': user,
            'timestamp': datetime.utcnow().isoformat()
        }]

    def to_dict(self, include_iocs=False):
        data = {
            'id': self.id,
            'uuid': str(self.uuid),
            'ticket_id': self.ticket_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'status': self.status,
            'assigned_to': self.assignee.username if self.assignee else None,
            'assigned_to_id': self.assigned_to,
            'created_by': self.creator.username if self.creator else None,
            'created_by_id': self.created_by,
            'session_id': self.session_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'timeline': self.timeline or [],
            'related_iocs': self.related_iocs or [],
            'ioc_count': self.linked_iocs.count() if self.linked_iocs else 0
        }
        if include_iocs:
            data['linked_iocs'] = [link.to_dict() for link in self.linked_iocs.all()]
        return data

    def __repr__(self):
        return f'<Incident {self.ticket_id}>'


class APIUsage(db.Model):
    """Modelo para tracking de uso de APIs"""
    __tablename__ = 'api_usage'

    id = db.Column(db.Integer, primary_key=True)
    api_name = db.Column(db.String(50), nullable=False, index=True)
    date = db.Column(db.Date, default=datetime.utcnow().date, index=True)
    requests_count = db.Column(db.Integer, default=0)
    errors_count = db.Column(db.Integer, default=0)
    last_request_at = db.Column(db.DateTime)

    # Estadísticas adicionales
    stats = db.Column(JSONB, default=dict)

    __table_args__ = (
        db.UniqueConstraint('api_name', 'date', name='unique_api_date'),
        db.Index('idx_api_usage_date', 'date', 'api_name'),
    )

    def __repr__(self):
        return f'<APIUsage {self.api_name} - {self.date}>'