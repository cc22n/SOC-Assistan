"""
STIX 2.1 Export Service
Sprint 5 - SOC Agent v2

Exporta IOCs y análisis en formato STIX 2.1 (Structured Threat Information Expression).
Permite compartir threat intelligence con otras plataformas SOC, SIEMs, y feeds TAXII.

Formatos de salida:
- STIX 2.1 Bundle (JSON)
- Individual STIX objects

Uso:
    from app.services.stix_exporter import STIXExporter
    exporter = STIXExporter()
    bundle = exporter.export_analysis(analysis_id=42)
    bundle = exporter.export_incident(incident_id=1)
"""
import json
import uuid
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# STIX 2.1 spec version
STIX_SPEC_VERSION = "2.1"

# Identity del SOC Agent (quién genera los objetos)
SOC_AGENT_IDENTITY_ID = "identity--soc-agent-platform"


class STIXExporter:
    """Exportador de IOCs y análisis a STIX 2.1"""

    def __init__(self):
        self.identity = self._create_identity()

    # -------------------------------------------------------------------------
    # EXPORTAR ANÁLISIS
    # -------------------------------------------------------------------------

    def export_analysis(self, analysis_id: int) -> Dict:
        """
        Exporta un análisis completo como STIX 2.1 Bundle.

        Incluye:
        - Indicator (el IOC con pattern)
        - Observed-Data (datos crudos de APIs)
        - Malware/Attack-Pattern (si se detectaron)
        - Relationships (vincula todo)
        """
        from app.models.ioc import IOCAnalysis, IOC

        analysis = IOCAnalysis.query.get(analysis_id)
        if not analysis:
            return {'error': f'Analysis {analysis_id} not found'}

        ioc = IOC.query.get(analysis.ioc_id)
        if not ioc:
            return {'error': 'IOC not found'}

        objects = [self.identity]

        # 1. Indicator (IOC principal)
        indicator = self._ioc_to_indicator(ioc, analysis)
        objects.append(indicator)

        # 2. MITRE Attack Patterns
        for technique in (analysis.mitre_techniques or []):
            if isinstance(technique, dict):
                tid = technique.get('id') or technique.get('technique_id', '')
                tname = technique.get('name', '')
            else:
                tid = str(technique)
                tname = ''

            if tid:
                ap = self._create_attack_pattern(tid, tname)
                objects.append(ap)
                rel = self._create_relationship(
                    indicator['id'], ap['id'], 'indicates'
                )
                objects.append(rel)

        # 3. Report (resumen del análisis)
        report = self._create_report(analysis, ioc, [o['id'] for o in objects])
        objects.append(report)

        return self._create_bundle(objects)

    def export_incident(self, incident_id: int) -> Dict:
        """Exporta un incidente completo como STIX Bundle"""
        from app.models.ioc import Incident, IncidentIOC, IOC, IOCAnalysis

        incident = Incident.query.get(incident_id)
        if not incident:
            return {'error': f'Incident {incident_id} not found'}

        objects = [self.identity]

        # Grouping (el incidente)
        grouping = self._incident_to_grouping(incident)

        # IOCs vinculados
        linked = IncidentIOC.query.filter_by(incident_id=incident_id).all()
        indicator_ids = []

        for link in linked:
            ioc = IOC.query.get(link.ioc_id)
            if not ioc:
                continue

            analysis = IOCAnalysis.query.get(link.analysis_id) if link.analysis_id else None
            indicator = self._ioc_to_indicator(ioc, analysis)
            objects.append(indicator)
            indicator_ids.append(indicator['id'])

        grouping['object_refs'] = indicator_ids
        objects.append(grouping)

        return self._create_bundle(objects)

    def export_iocs_bulk(self, ioc_ids: List[int]) -> Dict:
        """Exporta múltiples IOCs como STIX Bundle"""
        from app.models.ioc import IOC, IOCAnalysis

        objects = [self.identity]

        for ioc_id in ioc_ids:
            ioc = IOC.query.get(ioc_id)
            if not ioc:
                continue

            analysis = IOCAnalysis.query.filter_by(ioc_id=ioc_id).order_by(
                IOCAnalysis.created_at.desc()
            ).first()

            indicator = self._ioc_to_indicator(ioc, analysis)
            objects.append(indicator)

        return self._create_bundle(objects)

    # -------------------------------------------------------------------------
    # CREADORES DE OBJETOS STIX
    # -------------------------------------------------------------------------

    def _create_identity(self) -> Dict:
        """Identity object para SOC Agent"""
        return {
            'type': 'identity',
            'spec_version': STIX_SPEC_VERSION,
            'id': SOC_AGENT_IDENTITY_ID,
            'created': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z'),
            'modified': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z'),
            'name': 'SOC Agent Platform',
            'identity_class': 'system',
            'description': 'Automated threat intelligence analysis platform',
        }

    def _ioc_to_indicator(self, ioc, analysis=None) -> Dict:
        """Convierte un IOC a STIX Indicator"""
        pattern = self._build_stix_pattern(ioc.value, ioc.ioc_type)

        # Determinar TLP y confianza
        confidence = 0
        labels = ['malicious-activity']
        if analysis:
            confidence = min(analysis.confidence_score or 0, 100)
            risk = (analysis.risk_level or '').upper()
            if risk in ('LIMPIO', 'BAJO'):
                labels = ['benign']
            elif risk == 'MEDIO':
                labels = ['suspicious-activity']

        indicator = {
            'type': 'indicator',
            'spec_version': STIX_SPEC_VERSION,
            'id': f'indicator--{uuid.uuid5(uuid.NAMESPACE_URL, ioc.value)}',
            'created': ioc.first_seen.strftime('%Y-%m-%dT%H:%M:%S.000Z') if ioc.first_seen else datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z'),
            'modified': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z'),
            'name': f'{ioc.ioc_type.upper()}: {ioc.value}',
            'description': f'IOC analyzed by SOC Agent. Risk: {analysis.risk_level if analysis else "Unknown"}. Score: {analysis.confidence_score if analysis else 0}/100.',
            'pattern': pattern,
            'pattern_type': 'stix',
            'valid_from': ioc.first_seen.strftime('%Y-%m-%dT%H:%M:%S.000Z') if ioc.first_seen else datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z'),
            'indicator_types': labels,
            'confidence': confidence,
            'created_by_ref': SOC_AGENT_IDENTITY_ID,
        }

        # Agregar sources como external_references
        if analysis and analysis.sources_used:
            indicator['external_references'] = [
                {'source_name': src, 'description': f'Data from {src}'}
                for src in (analysis.sources_used or [])[:10]
            ]

        return indicator

    def _build_stix_pattern(self, value: str, ioc_type: str) -> str:
        """Genera un STIX pattern para un IOC"""
        patterns = {
            'ip': f"[ipv4-addr:value = '{value}']",
            'domain': f"[domain-name:value = '{value}']",
            'url': f"[url:value = '{value}']",
            'hash': self._hash_pattern(value),
        }
        return patterns.get(ioc_type, f"[artifact:payload_bin = '{value}']")

    def _hash_pattern(self, hash_value: str) -> str:
        """Detecta tipo de hash y genera STIX pattern"""
        length = len(hash_value)
        if length == 32:
            return f"[file:hashes.MD5 = '{hash_value}']"
        elif length == 40:
            return f"[file:hashes.'SHA-1' = '{hash_value}']"
        elif length == 64:
            return f"[file:hashes.'SHA-256' = '{hash_value}']"
        return f"[file:hashes.MD5 = '{hash_value}']"

    def _create_attack_pattern(self, technique_id: str, name: str = '') -> Dict:
        """Crea un STIX Attack Pattern desde un ID MITRE"""
        return {
            'type': 'attack-pattern',
            'spec_version': STIX_SPEC_VERSION,
            'id': f'attack-pattern--{uuid.uuid5(uuid.NAMESPACE_URL, technique_id)}',
            'created': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z'),
            'modified': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z'),
            'name': name or technique_id,
            'external_references': [{
                'source_name': 'mitre-attack',
                'external_id': technique_id,
                'url': f'https://attack.mitre.org/techniques/{technique_id.replace(".", "/")}/'
            }],
        }

    def _create_relationship(self, source_id: str, target_id: str,
                              relationship_type: str) -> Dict:
        """Crea una STIX Relationship"""
        return {
            'type': 'relationship',
            'spec_version': STIX_SPEC_VERSION,
            'id': f'relationship--{uuid.uuid4()}',
            'created': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z'),
            'modified': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z'),
            'relationship_type': relationship_type,
            'source_ref': source_id,
            'target_ref': target_id,
            'created_by_ref': SOC_AGENT_IDENTITY_ID,
        }

    def _create_report(self, analysis, ioc, object_refs: List[str]) -> Dict:
        """Crea un STIX Report del análisis"""
        return {
            'type': 'report',
            'spec_version': STIX_SPEC_VERSION,
            'id': f'report--{uuid.uuid5(uuid.NAMESPACE_URL, f"analysis-{analysis.id}")}',
            'created': analysis.created_at.strftime('%Y-%m-%dT%H:%M:%S.000Z') if analysis.created_at else datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z'),
            'modified': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z'),
            'name': f'SOC Agent Analysis: {ioc.value}',
            'description': f'Automated threat intelligence analysis. Risk Level: {analysis.risk_level}. Confidence: {analysis.confidence_score}/100. Sources: {", ".join(analysis.sources_used or [])}.',
            'report_types': ['threat-report'],
            'published': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z'),
            'object_refs': object_refs,
            'created_by_ref': SOC_AGENT_IDENTITY_ID,
        }

    def _incident_to_grouping(self, incident) -> Dict:
        """Convierte un Incident a STIX Grouping"""
        return {
            'type': 'grouping',
            'spec_version': STIX_SPEC_VERSION,
            'id': f'grouping--{uuid.uuid5(uuid.NAMESPACE_URL, f"incident-{incident.id}")}',
            'created': incident.created_at.strftime('%Y-%m-%dT%H:%M:%S.000Z') if incident.created_at else datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z'),
            'modified': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z'),
            'name': f'{incident.ticket_id}: {incident.title}',
            'description': incident.description or '',
            'context': 'suspicious-activity',
            'object_refs': [],
            'created_by_ref': SOC_AGENT_IDENTITY_ID,
        }

    def _create_bundle(self, objects: List[Dict]) -> Dict:
        """Empaqueta objetos en un STIX Bundle"""
        return {
            'type': 'bundle',
            'id': f'bundle--{uuid.uuid4()}',
            'objects': objects,
        }
