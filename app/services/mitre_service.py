"""
MITRE ATT&CK Dynamic Service
Sprint 5 - SOC Agent v2

Reemplaza el mitre.py hardcodeado con datos dinámicos:
1. Carga técnicas desde la API oficial MITRE ATT&CK (STIX/TAXII 2.1)
2. Cache en BD (tabla mitre_techniques) para no depender de conexión
3. Fallback a datos hardcodeados si la API no está disponible
4. Comando CLI para actualizar: flask mitre update

Fuente: https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
(JSON STIX bundle — más estable que el servidor TAXII que a veces falla)
"""
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

from app import db

logger = logging.getLogger(__name__)

# URL del bundle STIX oficial de MITRE (GitHub, siempre disponible)
MITRE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

# Cache TTL: cuánto tiempo antes de considerar datos obsoletos
CACHE_TTL_DAYS = 30


# =============================================================================
# MODELO DE BD
# =============================================================================

class MITRETechnique(db.Model):
    """Técnica MITRE ATT&CK almacenada en BD"""
    __tablename__ = 'mitre_techniques'

    id = db.Column(db.Integer, primary_key=True)
    technique_id = db.Column(db.String(20), unique=True, nullable=False, index=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    tactic = db.Column(db.String(50), index=True)
    tactics = db.Column(db.JSON, default=list)  # Una técnica puede tener múltiples tácticas
    platform = db.Column(db.JSON, default=list)  # Windows, Linux, macOS, etc.
    is_subtechnique = db.Column(db.Boolean, default=False)
    parent_id = db.Column(db.String(20))  # T1059 para T1059.001
    url = db.Column(db.String(500))
    data_sources = db.Column(db.JSON, default=list)
    detection = db.Column(db.Text)
    deprecated = db.Column(db.Boolean, default=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.technique_id,
            'name': self.name,
            'tactic': self.tactic,
            'tactics': self.tactics or [],
            'description': (self.description or '')[:500],
            'platform': self.platform or [],
            'is_subtechnique': self.is_subtechnique,
            'url': self.url,
            'data_sources': self.data_sources or [],
        }

    def __repr__(self):
        return f'<MITRETechnique {self.technique_id}: {self.name}>'


class MITREMalwareMapping(db.Model):
    """Mapeo de malware/software a técnicas MITRE"""
    __tablename__ = 'mitre_malware_mappings'

    id = db.Column(db.Integer, primary_key=True)
    malware_name = db.Column(db.String(200), nullable=False, index=True)
    malware_id = db.Column(db.String(20))  # S0001, etc.
    technique_ids = db.Column(db.JSON, default=list)
    aliases = db.Column(db.JSON, default=list)
    description = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('malware_name', name='unique_malware_name'),
    )

    def __repr__(self):
        return f'<MITREMalware {self.malware_name}>'


class MITREUpdateLog(db.Model):
    """Log de actualizaciones MITRE"""
    __tablename__ = 'mitre_update_log'

    id = db.Column(db.Integer, primary_key=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    techniques_count = db.Column(db.Integer, default=0)
    malware_count = db.Column(db.Integer, default=0)
    source = db.Column(db.String(100))  # 'stix_github', 'hardcoded_fallback'
    version = db.Column(db.String(50))  # ATT&CK version
    success = db.Column(db.Boolean, default=True)
    error = db.Column(db.Text)


# =============================================================================
# SERVICIO PRINCIPAL
# =============================================================================

class MITREService:
    """Servicio dinámico MITRE ATT&CK"""

    def __init__(self):
        self._cache = {}  # In-memory cache para búsquedas frecuentes
        self._cache_loaded = False

    # -------------------------------------------------------------------------
    # CONSULTAS (usadas por el resto de la app)
    # -------------------------------------------------------------------------

    def get_technique(self, technique_id: str) -> Optional[Dict]:
        """Busca una técnica por ID (ej: T1566.001)"""
        self._ensure_cache()

        if technique_id in self._cache:
            return self._cache[technique_id]

        # Buscar en BD
        tech = MITRETechnique.query.filter_by(technique_id=technique_id).first()
        if tech:
            result = tech.to_dict()
            self._cache[technique_id] = result
            return result

        # Fallback a datos hardcodeados
        from app.models.mitre import MITRE_TECHNIQUES_DB
        if technique_id in MITRE_TECHNIQUES_DB:
            info = MITRE_TECHNIQUES_DB[technique_id]
            return {
                'id': technique_id,
                'name': info['name'],
                'tactic': info['tactic'],
                'tactics': [info['tactic']],
                'description': '',
                'platform': [],
                'is_subtechnique': '.' in technique_id,
                'url': f'https://attack.mitre.org/techniques/{technique_id.replace(".", "/")}/',
                'data_sources': [],
            }

        return {'id': technique_id, 'name': 'Unknown Technique', 'tactic': 'Unknown'}

    def get_techniques_for_malware(self, malware_name: str) -> List[str]:
        """Busca técnicas asociadas a una familia de malware"""
        malware_lower = malware_name.lower().strip()

        # Buscar en BD
        mapping = MITREMalwareMapping.query.filter(
            db.func.lower(MITREMalwareMapping.malware_name) == malware_lower
        ).first()

        if not mapping:
            # Buscar en aliases
            mappings = MITREMalwareMapping.query.all()
            for m in mappings:
                aliases = [a.lower() for a in (m.aliases or [])]
                if malware_lower in aliases or malware_lower in m.malware_name.lower():
                    mapping = m
                    break

        if mapping:
            return mapping.technique_ids or []

        # Fallback hardcodeado
        from app.models.mitre import MALWARE_TO_TECHNIQUES
        for key, techniques in MALWARE_TO_TECHNIQUES.items():
            if key in malware_lower:
                return techniques

        return []

    def get_techniques_by_tactic(self, tactic: str) -> List[Dict]:
        """Todas las técnicas de una táctica"""
        techniques = MITRETechnique.query.filter(
            MITRETechnique.tactics.contains([tactic])
        ).all()

        if techniques:
            return [t.to_dict() for t in techniques]

        # Fallback
        from app.models.mitre import MITRE_TECHNIQUES_DB
        return [
            {'id': tid, 'name': info['name'], 'tactic': info['tactic']}
            for tid, info in MITRE_TECHNIQUES_DB.items()
            if info['tactic'] == tactic
        ]

    def search_techniques(self, query: str, limit: int = 20) -> List[Dict]:
        """Búsqueda de técnicas por nombre o ID"""
        q = query.strip().upper()
        techniques = MITRETechnique.query.filter(
            db.or_(
                MITRETechnique.technique_id.ilike(f'%{q}%'),
                MITRETechnique.name.ilike(f'%{query}%')
            )
        ).limit(limit).all()

        return [t.to_dict() for t in techniques]

    def get_all_tactics(self) -> List[str]:
        """Lista de tácticas disponibles"""
        from app.models.mitre import MITRE_TACTICS
        return MITRE_TACTICS

    def get_stats(self) -> Dict:
        """Estadísticas del dataset MITRE"""
        last_update = MITREUpdateLog.query.order_by(
            MITREUpdateLog.updated_at.desc()
        ).first()

        return {
            'techniques_in_db': MITRETechnique.query.count(),
            'malware_in_db': MITREMalwareMapping.query.count(),
            'last_update': last_update.updated_at.isoformat() if last_update else None,
            'source': last_update.source if last_update else 'none',
            'version': last_update.version if last_update else None,
            'cache_stale': self._is_cache_stale(),
        }

    # -------------------------------------------------------------------------
    # ACTUALIZACIÓN DESDE API OFICIAL
    # -------------------------------------------------------------------------

    def update_from_stix(self) -> Dict:
        """
        Descarga y parsea el bundle STIX de MITRE ATT&CK Enterprise.
        Actualiza las tablas mitre_techniques y mitre_malware_mappings.
        """
        import requests

        logger.info("Starting MITRE ATT&CK update from STIX bundle...")
        log = MITREUpdateLog(source='stix_github')

        try:
            # Descargar bundle
            resp = requests.get(MITRE_STIX_URL, timeout=60)
            resp.raise_for_status()
            bundle = resp.json()

            version = bundle.get('spec_version', 'unknown')
            objects = bundle.get('objects', [])
            logger.info(f"Downloaded STIX bundle: {len(objects)} objects, spec {version}")

            # Parsear técnicas
            techniques_count = self._parse_techniques(objects)

            # Parsear malware/software → técnicas
            malware_count = self._parse_malware_mappings(objects)

            # Registrar actualización
            log.techniques_count = techniques_count
            log.malware_count = malware_count
            log.version = version
            log.success = True

            db.session.add(log)
            db.session.commit()

            # Invalidar cache
            self._cache = {}
            self._cache_loaded = False

            result = {
                'success': True,
                'techniques': techniques_count,
                'malware_mappings': malware_count,
                'version': version,
            }
            logger.info(f"MITRE update complete: {result}")
            return result

        except Exception as e:
            logger.error(f"MITRE update failed: {e}", exc_info=True)
            log.success = False
            log.error = str(e)[:500]
            db.session.add(log)
            db.session.commit()
            return {'success': False, 'error': str(e)}

    def _parse_techniques(self, objects: List[Dict]) -> int:
        """Extrae técnicas del bundle STIX"""
        count = 0

        for obj in objects:
            if obj.get('type') != 'attack-pattern':
                continue
            if obj.get('revoked') or obj.get('x_mitre_deprecated'):
                continue

            # Extraer technique_id desde external_references
            ext_refs = obj.get('external_references', [])
            technique_id = None
            url = None
            for ref in ext_refs:
                if ref.get('source_name') == 'mitre-attack':
                    technique_id = ref.get('external_id')
                    url = ref.get('url')
                    break

            if not technique_id:
                continue

            # Extraer tácticas
            tactics = []
            for phase in obj.get('kill_chain_phases', []):
                if phase.get('kill_chain_name') == 'mitre-attack':
                    tactic = phase['phase_name'].replace('-', ' ').title()
                    tactics.append(tactic)

            # Upsert
            tech = MITRETechnique.query.filter_by(technique_id=technique_id).first()
            if not tech:
                tech = MITRETechnique(technique_id=technique_id)
                db.session.add(tech)

            tech.name = obj.get('name', 'Unknown')
            tech.description = obj.get('description', '')[:5000]
            tech.tactic = tactics[0] if tactics else 'Unknown'
            tech.tactics = tactics
            tech.platform = obj.get('x_mitre_platforms', [])
            tech.is_subtechnique = obj.get('x_mitre_is_subtechnique', False)
            tech.parent_id = technique_id.split('.')[0] if '.' in technique_id else None
            tech.url = url
            tech.data_sources = obj.get('x_mitre_data_sources', [])
            tech.detection = obj.get('x_mitre_detection', '')[:5000] if obj.get('x_mitre_detection') else None
            tech.deprecated = False
            tech.updated_at = datetime.utcnow()

            count += 1

        db.session.flush()
        logger.info(f"Parsed {count} techniques from STIX bundle")
        return count

    def _parse_malware_mappings(self, objects: List[Dict]) -> int:
        """Extrae software/malware y sus relaciones con técnicas"""
        # Paso 1: Indexar software (malware + tool)
        software = {}
        for obj in objects:
            if obj.get('type') not in ('malware', 'tool'):
                continue
            if obj.get('revoked') or obj.get('x_mitre_deprecated'):
                continue

            stix_id = obj['id']
            ext_refs = obj.get('external_references', [])
            malware_id = None
            for ref in ext_refs:
                if ref.get('source_name') == 'mitre-attack':
                    malware_id = ref.get('external_id')
                    break

            software[stix_id] = {
                'name': obj.get('name', 'Unknown'),
                'malware_id': malware_id,
                'aliases': obj.get('x_mitre_aliases', []),
                'description': obj.get('description', '')[:2000],
                'techniques': [],
            }

        # Paso 2: Mapear relationships (software → technique)
        for obj in objects:
            if obj.get('type') != 'relationship':
                continue
            if obj.get('relationship_type') != 'uses':
                continue

            source = obj.get('source_ref', '')
            target = obj.get('target_ref', '')

            # software "uses" attack-pattern
            if source in software and target.startswith('attack-pattern'):
                # Buscar technique_id del target
                for inner in objects:
                    if inner.get('id') == target and inner.get('type') == 'attack-pattern':
                        for ref in inner.get('external_references', []):
                            if ref.get('source_name') == 'mitre-attack':
                                software[source]['techniques'].append(ref['external_id'])
                                break
                        break

        # Paso 3: Guardar en BD
        count = 0
        for stix_id, info in software.items():
            if not info['techniques']:
                continue

            name_lower = info['name'].lower()
            mapping = MITREMalwareMapping.query.filter(
                db.func.lower(MITREMalwareMapping.malware_name) == name_lower
            ).first()

            if not mapping:
                mapping = MITREMalwareMapping(malware_name=info['name'])
                db.session.add(mapping)

            mapping.malware_id = info['malware_id']
            mapping.technique_ids = list(set(info['techniques']))
            mapping.aliases = info['aliases']
            mapping.description = info['description']
            mapping.updated_at = datetime.utcnow()
            count += 1

        db.session.flush()
        logger.info(f"Parsed {count} malware/software mappings from STIX bundle")
        return count

    # -------------------------------------------------------------------------
    # HELPERS
    # -------------------------------------------------------------------------

    def _ensure_cache(self):
        """Carga cache en memoria si está vacío"""
        if self._cache_loaded:
            return
        techniques = MITRETechnique.query.limit(1).all()
        if techniques:
            for tech in MITRETechnique.query.all():
                self._cache[tech.technique_id] = tech.to_dict()
            self._cache_loaded = True

    def _is_cache_stale(self) -> bool:
        """Verifica si los datos necesitan actualización"""
        last = MITREUpdateLog.query.filter_by(success=True).order_by(
            MITREUpdateLog.updated_at.desc()
        ).first()
        if not last:
            return True
        return datetime.utcnow() - last.updated_at > timedelta(days=CACHE_TTL_DAYS)

    def needs_update(self) -> bool:
        """True si nunca se cargaron datos o están obsoletos"""
        count = MITRETechnique.query.count()
        if count == 0:
            return True
        return self._is_cache_stale()


# =============================================================================
# SINGLETON
# =============================================================================

_mitre_service = None

def get_mitre_service() -> MITREService:
    global _mitre_service
    if _mitre_service is None:
        _mitre_service = MITREService()
    return _mitre_service


# =============================================================================
# FUNCIONES DE COMPATIBILIDAD (reemplazan las de mitre.py hardcodeado)
# =============================================================================

def get_technique_info(technique_id: str) -> dict:
    """Drop-in replacement para mitre.get_technique_info()"""
    svc = get_mitre_service()
    result = svc.get_technique(technique_id)
    return {'name': result.get('name', 'Unknown'), 'tactic': result.get('tactic', 'Unknown')}


def get_techniques_by_malware(malware_name: str) -> list:
    """Drop-in replacement para mitre.get_techniques_by_malware()"""
    svc = get_mitre_service()
    return svc.get_techniques_for_malware(malware_name)


def get_techniques_by_tactic(tactic: str) -> list:
    """Drop-in replacement para mitre.get_techniques_by_tactic()"""
    svc = get_mitre_service()
    return svc.get_techniques_by_tactic(tactic)
