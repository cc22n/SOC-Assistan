"""
Feeds proactivos de CVEs (WP6 de PLAN-FUSION): inteligencia que llega sola, filtrada por lo que la organización ejecuta.

  * TechStackEntry  tecnología declarada (vendor y/o producto). Es global: el stack es de la organización, no de un usuario.
  * FeedItem        UN registro por CVE (no por fuente): si un CVE ya conocido entra después en KEV se ESCALA en vez de
                    duplicarse (`escalated_at`).
  * FeedRun         bitácora de cada ejecución de una fuente (para ver si el feed está vivo y cuánto retraso lleva).

Origen: CTI Summarizer (adaptadores de ingesta + normalización + Celery Beat). Lo nuevo respecto a él, que es la razón de
ser del WP: la RELEVANCIA contra el stack declarado.
"""
from sqlalchemy import Index, func
from sqlalchemy.dialects.postgresql import JSONB

from app import db
from app.utils.time_utils import utcnow


class TechStackEntry(db.Model):
    __tablename__ = 'tech_stack_entries'

    id = db.Column(db.Integer, primary_key=True)
    vendor = db.Column(db.String(120), nullable=True)      # al menos uno de vendor/producto
    product = db.Column(db.String(120), nullable=True)
    note = db.Column(db.String(300), nullable=False, default='')
    created_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    __table_args__ = (
        Index('uq_tech_stack_vendor_product', func.lower(func.coalesce(vendor, '')),
              func.lower(func.coalesce(product, '')), unique=True),
    )

    def to_dict(self):
        return {'id': self.id, 'vendor': self.vendor, 'product': self.product, 'note': self.note,
                'created_by': self.created_by, 'created_at': self.created_at.isoformat() if self.created_at else None}

    def label(self) -> str:
        return ' '.join(x for x in (self.vendor, self.product) if x)


class FeedItem(db.Model):
    __tablename__ = 'feed_items'

    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(30), nullable=False, unique=True)
    title = db.Column(db.String(300), nullable=False, default='')
    summary = db.Column(db.Text, nullable=False, default='')
    published_at = db.Column(db.DateTime, nullable=True, index=True)     # publicación en NVD o alta en KEV, la más temprana
    sources = db.Column(JSONB, nullable=False, default=list)             # ['cisa_kev', 'nvd_recent']
    affected = db.Column(JSONB, nullable=False, default=list)            # [{'vendor': .., 'product': ..}]
    in_kev = db.Column(db.Boolean, nullable=False, default=False)
    kev_date_added = db.Column(db.Date, nullable=True)
    known_ransomware = db.Column(db.Boolean, nullable=False, default=False)
    cvss_score = db.Column(db.Float, nullable=True)
    epss = db.Column(db.Float, nullable=True)                            # NULL = aún sin puntuar (los CVE frescos lo están)
    priority_score = db.Column(db.Integer, nullable=False, default=0)
    risk_level = db.Column(db.String(20), nullable=False, default='BAJO', index=True)
    is_relevant = db.Column(db.Boolean, nullable=False, default=False, index=True)
    matched_entries = db.Column(JSONB, nullable=False, default=list)     # ids de TechStackEntry que casaron
    escalated_at = db.Column(db.DateTime, nullable=True)                 # entró en KEV después de conocerse
    first_seen_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    def to_dict(self):
        return {
            'cve_id': self.cve_id, 'title': self.title, 'summary': self.summary,
            'published_at': self.published_at.isoformat() if self.published_at else None,
            'sources': list(self.sources or []), 'affected': list(self.affected or []),
            'in_kev': self.in_kev, 'kev_date_added': self.kev_date_added.isoformat() if self.kev_date_added else None,
            'known_ransomware': self.known_ransomware, 'cvss_score': self.cvss_score, 'epss': self.epss,
            'priority_score': self.priority_score, 'risk_level': self.risk_level,
            'is_relevant': self.is_relevant, 'matched_entries': list(self.matched_entries or []),
            'escalated_at': self.escalated_at.isoformat() if self.escalated_at else None,
            'first_seen_at': self.first_seen_at.isoformat() if self.first_seen_at else None,
        }


class FeedRun(db.Model):
    __tablename__ = 'feed_runs'

    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String(30), nullable=False, index=True)
    started_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
    finished_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(10), nullable=False, default='running')   # running | ok | error
    fetched = db.Column(db.Integer, nullable=False, default=0)
    new_items = db.Column(db.Integer, nullable=False, default=0)
    updated_items = db.Column(db.Integer, nullable=False, default=0)
    relevant_new = db.Column(db.Integer, nullable=False, default=0)        # nuevos o escalados que casan con el stack
    error = db.Column(db.String(500), nullable=True)

    def to_dict(self):
        return {'id': self.id, 'source': self.source, 'status': self.status, 'fetched': self.fetched,
                'new_items': self.new_items, 'updated_items': self.updated_items, 'relevant_new': self.relevant_new,
                'started_at': self.started_at.isoformat() if self.started_at else None,
                'finished_at': self.finished_at.isoformat() if self.finished_at else None, 'error': self.error}
