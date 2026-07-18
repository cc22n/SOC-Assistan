"""
Tests unitarios — app/services/stix_exporter.py (STIXExporter)

Cubre la generación del bundle STIX 2.1 en sí (no las rutas HTTP — esas ya
tienen cobertura de IDOR en tests/unit/test_mitre_stix_routes.py):
- export_analysis: bundle válido con identity/indicator/report, attack-patterns
  y relationships cuando hay mitre_techniques
- export_analysis: IOC sin mitre_techniques -> no hay attack-pattern
- export_analysis: analysis inexistente -> dict con 'error'
- export_analysis: análisis con campos nulos (sources_used, confidence_score)
  no lanza excepción
- export_incident: bundle con grouping + indicators de los IOCs vinculados
- export_incident: incidente inexistente -> dict con 'error'
- export_iocs_bulk: múltiples IOCs, incluido uno sin análisis
- _build_stix_pattern / _hash_pattern: patrones STIX por tipo de IOC y longitud de hash
"""
import pytest

from app.services.stix_exporter import STIXExporter, SOC_AGENT_IDENTITY_ID


@pytest.fixture
def exporter():
    return STIXExporter()


def _objects_by_type(bundle, obj_type):
    return [o for o in bundle['objects'] if o.get('type') == obj_type]


# ==============================================================================
# export_analysis
# ==============================================================================

class TestExportAnalysis:

    def test_returns_valid_bundle_with_indicator_and_report(self, app, db_session, exporter, sample_analysis):
        with app.app_context():
            bundle = exporter.export_analysis(sample_analysis.id)

            assert bundle['type'] == 'bundle'
            assert bundle['id'].startswith('bundle--')
            assert isinstance(bundle['objects'], list)

            identities = _objects_by_type(bundle, 'identity')
            assert len(identities) == 1
            assert identities[0]['id'] == SOC_AGENT_IDENTITY_ID

            indicators = _objects_by_type(bundle, 'indicator')
            assert len(indicators) == 1
            indicator = indicators[0]
            assert indicator['id'].startswith('indicator--')
            assert indicator['pattern_type'] == 'stix'
            assert '185.220.101.34' in indicator['pattern']
            assert indicator['confidence'] == sample_analysis.confidence_score
            assert indicator['created_by_ref'] == SOC_AGENT_IDENTITY_ID

            reports = _objects_by_type(bundle, 'report')
            assert len(reports) == 1
            assert reports[0]['object_refs']  # incluye referencias a otros objetos

    def test_no_mitre_techniques_produces_no_attack_pattern(self, app, db_session, exporter, sample_analysis):
        with app.app_context():
            # sample_analysis no trae mitre_techniques -> default es None/[]
            assert not sample_analysis.mitre_techniques

            bundle = exporter.export_analysis(sample_analysis.id)

            assert _objects_by_type(bundle, 'attack-pattern') == []
            assert _objects_by_type(bundle, 'relationship') == []

    def test_mitre_techniques_produce_attack_pattern_and_relationship(
        self, app, db_session, exporter, sample_ioc, analyst_user
    ):
        from app.models.ioc import IOCAnalysis
        from app import db

        with app.app_context():
            analysis = IOCAnalysis(
                ioc_id=sample_ioc.id,
                user_id=analyst_user.id,
                confidence_score=90,
                risk_level='CRÍTICO',
                recommendation='Bloquear inmediatamente.',
                sources_used=['virustotal'],
                mitre_techniques=[
                    {'id': 'T1071', 'name': 'Application Layer Protocol'},
                    'T1105',
                ],
            )
            db.session.add(analysis)
            db.session.commit()

            bundle = exporter.export_analysis(analysis.id)

            attack_patterns = _objects_by_type(bundle, 'attack-pattern')
            assert len(attack_patterns) == 2
            names = {ap['name'] for ap in attack_patterns}
            assert 'Application Layer Protocol' in names
            assert 'T1105' in names  # sin nombre, usa el id como name

            relationships = _objects_by_type(bundle, 'relationship')
            assert len(relationships) == 2
            for rel in relationships:
                assert rel['relationship_type'] == 'indicates'

    def test_nonexistent_analysis_returns_error(self, app, db_session, exporter):
        with app.app_context():
            result = exporter.export_analysis(999999)
            assert 'error' in result

    def test_null_fields_do_not_raise(self, app, db_session, exporter, sample_ioc, analyst_user):
        """confidence_score y sources_used nulos no deben romper la exportación."""
        from app.models.ioc import IOCAnalysis
        from app import db

        with app.app_context():
            analysis = IOCAnalysis(
                ioc_id=sample_ioc.id,
                user_id=analyst_user.id,
                confidence_score=None,
                risk_level='MEDIO',
                recommendation='Monitorear.',
                sources_used=None,
            )
            db.session.add(analysis)
            db.session.commit()

            bundle = exporter.export_analysis(analysis.id)

            assert bundle['type'] == 'bundle'
            indicator = _objects_by_type(bundle, 'indicator')[0]
            assert indicator['confidence'] == 0
            assert 'external_references' not in indicator


# ==============================================================================
# export_incident
# ==============================================================================

class TestExportIncident:

    def test_returns_bundle_with_grouping_and_linked_indicators(
        self, app, db_session, exporter, sample_incident, sample_ioc, sample_analysis
    ):
        from app.models.ioc import IncidentIOC
        from app import db

        with app.app_context():
            link = IncidentIOC(
                incident_id=sample_incident.id,
                ioc_id=sample_ioc.id,
                analysis_id=sample_analysis.id,
                role='primary',
            )
            db.session.add(link)
            db.session.commit()

            bundle = exporter.export_incident(sample_incident.id)

            assert bundle['type'] == 'bundle'
            groupings = _objects_by_type(bundle, 'grouping')
            assert len(groupings) == 1
            grouping = groupings[0]
            assert sample_incident.ticket_id in grouping['name']

            indicators = _objects_by_type(bundle, 'indicator')
            assert len(indicators) == 1
            assert indicators[0]['id'] in grouping['object_refs']

    def test_incident_without_linked_iocs_still_returns_bundle(self, app, db_session, exporter, sample_incident):
        with app.app_context():
            bundle = exporter.export_incident(sample_incident.id)

            assert bundle['type'] == 'bundle'
            groupings = _objects_by_type(bundle, 'grouping')
            assert len(groupings) == 1
            assert groupings[0]['object_refs'] == []

    def test_nonexistent_incident_returns_error(self, app, db_session, exporter):
        with app.app_context():
            result = exporter.export_incident(999999)
            assert 'error' in result


# ==============================================================================
# export_iocs_bulk
# ==============================================================================

class TestExportIocsBulk:

    def test_exports_multiple_iocs_including_one_without_analysis(
        self, app, db_session, exporter, sample_ioc, sample_analysis
    ):
        from app.models.ioc import IOC
        from app import db

        with app.app_context():
            clean_ioc = IOC(value='8.8.8.8', ioc_type='ip', is_whitelisted=False)
            db.session.add(clean_ioc)
            db.session.commit()
            db.session.refresh(clean_ioc)

            bundle = exporter.export_iocs_bulk([sample_ioc.id, clean_ioc.id])

            indicators = _objects_by_type(bundle, 'indicator')
            assert len(indicators) == 2

            values = {ind['pattern'] for ind in indicators}
            assert any('185.220.101.34' in v for v in values)
            assert any('8.8.8.8' in v for v in values)

    def test_skips_nonexistent_ioc_ids(self, app, db_session, exporter, sample_ioc):
        with app.app_context():
            bundle = exporter.export_iocs_bulk([sample_ioc.id, 999999])

            indicators = _objects_by_type(bundle, 'indicator')
            assert len(indicators) == 1


# ==============================================================================
# Patrones STIX por tipo / hash
# ==============================================================================

class TestStixPatterns:

    def test_ip_pattern(self, exporter):
        assert exporter._build_stix_pattern('1.2.3.4', 'ip') == "[ipv4-addr:value = '1.2.3.4']"

    def test_domain_pattern(self, exporter):
        assert exporter._build_stix_pattern('evil.com', 'domain') == "[domain-name:value = 'evil.com']"

    def test_url_pattern(self, exporter):
        assert exporter._build_stix_pattern('http://evil.com', 'url') == "[url:value = 'http://evil.com']"

    def test_hash_pattern_md5(self, exporter):
        md5 = 'a' * 32
        pattern = exporter._build_stix_pattern(md5, 'hash')
        assert 'file:hashes.MD5' in pattern

    def test_hash_pattern_sha1(self, exporter):
        sha1 = 'a' * 40
        pattern = exporter._build_stix_pattern(sha1, 'hash')
        assert "file:hashes.'SHA-1'" in pattern

    def test_hash_pattern_sha256(self, exporter):
        sha256 = 'a' * 64
        pattern = exporter._build_stix_pattern(sha256, 'hash')
        assert "file:hashes.'SHA-256'" in pattern

    def test_unknown_type_falls_back_to_artifact(self, exporter):
        pattern = exporter._build_stix_pattern('something', 'unknown_type')
        assert pattern == "[artifact:payload_bin = 'something']"
