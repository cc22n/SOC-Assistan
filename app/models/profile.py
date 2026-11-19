"""
Perfiles de investigación: una consulta REPETIBLE definida por el analista.

Un perfil fija para un tipo de IOC QUÉ APIs se consultan (en paralelo), sin que decida el planificador LLM
(`select_apis_for_ioc`): misma consulta, mismo coste y mismo conjunto de fuentes cada vez. El modo automático
sigue siendo el predeterminado.

Origen: SOC Forge (apps/profiles). Se simplificó a propósito: una sola tabla con la lista ordenada de APIs en JSONB
(sin tablas de configuración por fuente ni "campos esperados") y sin timeouts por fuente.

Los nombres de API NO se hardcodean aquí: se validan contra `IOCAnalysis.api_source_names()` y
`LLMOrchestrator._is_api_compatible` (ver app/services/profile_service.py).
"""
from sqlalchemy import Index, func
from sqlalchemy.dialects.postgresql import JSONB

from app import db
from app.utils.time_utils import utcnow


class InvestigationProfile(db.Model):
    __tablename__ = 'investigation_profiles'

    MAX_APIS = 10

    id = db.Column(db.Integer, primary_key=True)
    # NULL = perfil del sistema o de un usuario borrado (el perfil es configuración, sobrevive al analista)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False, default='')
    ioc_type = db.Column(db.String(20), nullable=False, index=True)       # ip | domain | url | hash
    apis = db.Column(JSONB, nullable=False, default=list)                 # ['virustotal', ...]; se consultan en PARALELO (el orden es solo de presentación)
    llm_synthesis = db.Column(db.Boolean, nullable=False, default=True)   # False: sin LLM, solo datos de las fuentes
    is_system = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    # un nombre por dueño, sin distinguir mayúsculas (los perfiles del sistema comparten owner NULL -> 0)
    __table_args__ = (
        Index('uq_investigation_profile_owner_name', func.coalesce(owner_id, 0), func.lower(name), unique=True),
    )

    def is_visible_to(self, user) -> bool:
        """Los del sistema los ven todos; los demás, su dueño y los admin."""
        if self.is_system:
            return True
        return bool(user and user.is_authenticated and (user.role == 'admin' or self.owner_id == user.id))

    def is_editable_by(self, user) -> bool:
        """Los del sistema son inmutables por la API; los demás, solo su dueño o un admin."""
        if self.is_system:
            return False
        return bool(user and user.is_authenticated and (user.role == 'admin' or self.owner_id == user.id))

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'ioc_type': self.ioc_type,
            'apis': list(self.apis or []),
            'llm_synthesis': self.llm_synthesis,
            'is_system': self.is_system,
            'owner_id': self.owner_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self):
        return f'<InvestigationProfile {self.id} {self.name!r} {self.ioc_type}>'
