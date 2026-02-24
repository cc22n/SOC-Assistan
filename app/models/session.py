"""
Modelos SQLAlchemy para Sesiones de Investigación
SOC Agent - Fase 1.5

Tablas:
- InvestigationSession: Sesiones que agrupan IOCs y mensajes
- SessionIOC: IOCs vinculados a una sesión
- SessionMessage: Mensajes del chat en una sesión
"""
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, DateTime,
    ForeignKey, ARRAY, CheckConstraint, Index
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship, backref
from sqlalchemy.sql import func
import uuid

from app import db


class InvestigationSession(db.Model):
    """
    Sesión de investigación que agrupa IOCs y mensajes de chat.
    Permite mantener contexto entre múltiples análisis relacionados.
    """
    __tablename__ = 'investigation_sessions'

    # Primary key
    id = Column(Integer, primary_key=True)
    uuid = Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False)

    # Foreign keys
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    incident_id = Column(Integer, ForeignKey('incidents.id', ondelete='SET NULL'), nullable=True)

    # Metadatos
    title = Column(String(200), nullable=True)
    description = Column(Text, nullable=True)
    status = Column(
        String(20),
        default='active',
        nullable=False
    )

    # Timestamps
    created_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    closed_at = Column(DateTime(timezone=True), nullable=True)
    last_activity_at = Column(DateTime(timezone=True), default=func.now())

    # Estadísticas (actualizadas por triggers en BD)
    total_iocs = Column(Integer, default=0)
    total_messages = Column(Integer, default=0)
    highest_risk_level = Column(String(20), nullable=True)

    # Resumen comprimido para contexto LLM
    compressed_summary = Column(Text, nullable=True)
    summary_updated_at = Column(DateTime(timezone=True), nullable=True)

    # Configuración
    auto_close_hours = Column(Integer, default=24)
    preferred_llm_provider = Column(String(20), nullable=True)

    # Relationships
    user = relationship('User', backref=backref('investigation_sessions', lazy='dynamic'))
    incident = relationship('Incident', backref=backref('investigation_sessions', lazy='dynamic'),
                            foreign_keys=[incident_id])
    iocs = relationship('SessionIOC', back_populates='session', lazy='dynamic', cascade='all, delete-orphan')
    messages = relationship('SessionMessage', back_populates='session', lazy='dynamic', cascade='all, delete-orphan',
                            order_by='SessionMessage.created_at')

    # Constraints
    __table_args__ = (
        CheckConstraint(status.in_(['active', 'paused', 'closed', 'archived']), name='check_session_status'),
        Index('idx_sessions_user_active', user_id, status, postgresql_where=(status == 'active')),
        Index('idx_sessions_last_activity', last_activity_at.desc()),
    )

    def __repr__(self):
        return f'<InvestigationSession {self.id}: {self.title or "Sin título"}>'

    def to_dict(self, include_iocs: bool = False, include_messages: bool = False) -> Dict[str, Any]:
        """Convierte la sesión a diccionario"""
        data = {
            'id': self.id,
            'uuid': str(self.uuid),
            'user_id': self.user_id,
            'title': self.title,
            'description': self.description,
            'status': self.status,
            'total_iocs': self.total_iocs,
            'total_messages': self.total_messages,
            'highest_risk_level': self.highest_risk_level,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'last_activity_at': self.last_activity_at.isoformat() if self.last_activity_at else None,
            'closed_at': self.closed_at.isoformat() if self.closed_at else None,
            'auto_close_hours': self.auto_close_hours,
            'preferred_llm_provider': self.preferred_llm_provider,
            'hours_until_auto_close': self.hours_until_auto_close
        }

        if include_iocs:
            data['iocs'] = [ioc.to_dict() for ioc in self.iocs.all()]

        if include_messages:
            data['messages'] = [msg.to_dict() for msg in self.messages.all()]

        return data

    @property
    def hours_until_auto_close(self) -> Optional[float]:
        """Calcula horas restantes antes del auto-cierre"""
        if self.status != 'active' or not self.last_activity_at:
            return None

        elapsed = datetime.utcnow() - self.last_activity_at.replace(tzinfo=None)
        remaining = self.auto_close_hours - (elapsed.total_seconds() / 3600)
        return max(0, round(remaining, 2))

    @property
    def is_expired(self) -> bool:
        """Verifica si la sesión debería auto-cerrarse"""
        if self.status != 'active':
            return False

        hours = self.hours_until_auto_close
        return hours is not None and hours <= 0

    def update_activity(self):
        """Actualiza timestamp de última actividad"""
        self.last_activity_at = datetime.utcnow()

    def close(self):
        """Cierra la sesión"""
        self.status = 'closed'
        self.closed_at = datetime.utcnow()

    def generate_title(self, ioc_value: str = None, ioc_type: str = None) -> str:
        """Genera título automático basado en el primer IOC"""
        if ioc_value and ioc_type:
            # Truncar IOC largo
            display_ioc = ioc_value[:20] + '...' if len(ioc_value) > 20 else ioc_value
            date_str = datetime.utcnow().strftime('%d %b %Y')
            return f"Investigación {ioc_type} {display_ioc} - {date_str}"
        else:
            date_str = datetime.utcnow().strftime('%d %b %Y %H:%M')
            return f"Nueva investigación - {date_str}"


class SessionIOC(db.Model):
    """
    Vincula IOCs a sesiones de investigación.
    Permite trackear qué IOCs se analizaron en cada sesión.
    """
    __tablename__ = 'session_iocs'

    # Primary key
    id = Column(Integer, primary_key=True)

    # Foreign keys
    session_id = Column(Integer, ForeignKey('investigation_sessions.id', ondelete='CASCADE'), nullable=False)
    ioc_id = Column(Integer, ForeignKey('iocs.id', ondelete='CASCADE'), nullable=False)
    analysis_id = Column(Integer, ForeignKey('ioc_analyses.id', ondelete='SET NULL'), nullable=True)

    # Contexto
    role = Column(String(20), default='analyzed')
    added_at = Column(DateTime(timezone=True), default=func.now())
    added_by_message_id = Column(Integer, nullable=True)

    # Notas del analista
    analyst_notes = Column(Text, nullable=True)

    # Relaciones con otros IOCs
    related_to_ioc_ids = Column(ARRAY(Integer), nullable=True)
    relationship_type = Column(String(50), nullable=True)

    # Relationships
    session = relationship('InvestigationSession', back_populates='iocs')
    ioc = relationship('IOC', backref=backref('session_links', lazy='dynamic'))
    analysis = relationship('IOCAnalysis', backref=backref('session_links', lazy='dynamic'))

    # Constraints
    __table_args__ = (
        CheckConstraint(role.in_(['primary', 'related', 'context', 'analyzed']), name='check_ioc_role'),
        db.UniqueConstraint('session_id', 'ioc_id', name='unique_session_ioc'),
        Index('idx_session_iocs_session', session_id),
        Index('idx_session_iocs_ioc', ioc_id),
    )

    def __repr__(self):
        return f'<SessionIOC session={self.session_id} ioc={self.ioc_id}>'

    def to_dict(self) -> Dict[str, Any]:
        """Convierte a diccionario"""
        return {
            'id': self.id,
            'session_id': self.session_id,
            'ioc_id': self.ioc_id,
            'ioc_value': self.ioc.value if self.ioc else None,
            'ioc_type': self.ioc.ioc_type if self.ioc else None,
            'analysis_id': self.analysis_id,
            'role': self.role,
            'added_at': self.added_at.isoformat() if self.added_at else None,
            'analyst_notes': self.analyst_notes,
            'risk_level': self.analysis.risk_level if self.analysis else None,
            'confidence_score': self.analysis.confidence_score if self.analysis else None,
            'related_to_ioc_ids': self.related_to_ioc_ids,
            'relationship_type': self.relationship_type
        }


class SessionMessage(db.Model):
    """
    Mensajes del chat dentro de una sesión.
    Permite reconstruir la conversación y mantener contexto.
    """
    __tablename__ = 'session_messages'

    # Primary key
    id = Column(Integer, primary_key=True)

    # Foreign keys
    session_id = Column(Integer, ForeignKey('investigation_sessions.id', ondelete='CASCADE'), nullable=False)
    analysis_id = Column(Integer, ForeignKey('ioc_analyses.id', ondelete='SET NULL'), nullable=True)

    # Contenido
    role = Column(String(20), nullable=False)
    content = Column(Text, nullable=False)

    # Metadatos
    created_at = Column(DateTime(timezone=True), default=func.now())

    # Referencias
    iocs_mentioned = Column(ARRAY(Text), nullable=True)
    analysis_triggered = Column(Boolean, default=False)

    # Control de contexto
    is_summary = Column(Boolean, default=False)
    tokens_estimated = Column(Integer, nullable=True)

    # LLM que generó la respuesta
    llm_provider = Column(String(20), nullable=True)

    # Relationships
    session = relationship('InvestigationSession', back_populates='messages')
    analysis = relationship('IOCAnalysis', backref=backref('session_messages', lazy='dynamic'))

    # Constraints
    __table_args__ = (
        CheckConstraint(role.in_(['user', 'assistant', 'system']), name='check_message_role'),
        Index('idx_session_messages_session', session_id),
        Index('idx_session_messages_session_created', session_id, created_at.desc()),
    )

    def __repr__(self):
        preview = self.content[:50] + '...' if len(self.content) > 50 else self.content
        return f'<SessionMessage {self.role}: {preview}>'

    def to_dict(self) -> Dict[str, Any]:
        """Convierte a diccionario"""
        return {
            'id': self.id,
            'session_id': self.session_id,
            'role': self.role,
            'content': self.content,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'iocs_mentioned': self.iocs_mentioned,
            'analysis_triggered': self.analysis_triggered,
            'analysis_id': self.analysis_id,
            'is_summary': self.is_summary,
            'tokens_estimated': self.tokens_estimated,
            'llm_provider': self.llm_provider
        }

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Estima tokens de un texto (aproximación: 1 token ≈ 4 caracteres)"""
        return len(text) // 4


# ============================================================================
# FUNCIONES HELPER
# ============================================================================

def get_active_session_for_user(user_id: int) -> Optional[InvestigationSession]:
    """
    Obtiene la sesión activa más reciente para un usuario.
    Retorna None si no hay sesión activa.
    """
    return InvestigationSession.query.filter_by(
        user_id=user_id,
        status='active'
    ).order_by(InvestigationSession.last_activity_at.desc()).first()


def get_or_create_session(user_id: int, title: str = None) -> InvestigationSession:
    """
    Obtiene sesión activa existente o crea una nueva.
    """
    session = get_active_session_for_user(user_id)

    if session and not session.is_expired:
        session.update_activity()
        db.session.commit()
        return session

    # Crear nueva sesión
    new_session = InvestigationSession(
        user_id=user_id,
        title=title or InvestigationSession().generate_title(),
        status='active'
    )
    db.session.add(new_session)
    db.session.commit()

    return new_session


def close_expired_sessions() -> int:
    """
    Cierra todas las sesiones que han expirado.
    Retorna el número de sesiones cerradas.
    """
    expired = InvestigationSession.query.filter(
        InvestigationSession.status == 'active',
        InvestigationSession.last_activity_at < datetime.utcnow() - timedelta(hours=24)
    ).all()

    count = 0
    for session in expired:
        if session.is_expired:
            session.close()
            count += 1

    db.session.commit()
    return count