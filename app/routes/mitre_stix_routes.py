"""
MITRE ATT&CK + STIX Export Routes
Sprint 5 - SOC Agent v2

Endpoints:
- GET  /api/v2/mitre/techniques       - Buscar técnicas
- GET  /api/v2/mitre/techniques/{id}  - Detalle de técnica
- GET  /api/v2/mitre/tactics           - Lista de tácticas
- GET  /api/v2/mitre/malware/{name}   - Técnicas por malware
- GET  /api/v2/mitre/stats             - Estadísticas del dataset
- POST /api/v2/mitre/update            - Actualizar desde MITRE (admin)
- GET  /api/v2/stix/analysis/{id}      - Exportar análisis como STIX
- GET  /api/v2/stix/incident/{id}      - Exportar incidente como STIX
- POST /api/v2/stix/bulk               - Exportar múltiples IOCs como STIX
"""
from flask import Blueprint, request, jsonify, Response
from flask_login import login_required, current_user
import json
import logging

logger = logging.getLogger(__name__)

bp = Blueprint('mitre_stix', __name__, url_prefix='/api/v2')


# =============================================================================
# MITRE ATT&CK ENDPOINTS
# =============================================================================

@bp.route('/mitre/techniques', methods=['GET'])
@login_required
def search_techniques():
    """Buscar técnicas MITRE por nombre o ID"""
    try:
        from app.services.mitre_service import get_mitre_service
        svc = get_mitre_service()

        query = request.args.get('q', '').strip()
        tactic = request.args.get('tactic')
        limit = request.args.get('limit', 20, type=int)

        if tactic:
            techniques = svc.get_techniques_by_tactic(tactic)
        elif query:
            techniques = svc.search_techniques(query, limit=limit)
        else:
            techniques = svc.search_techniques('T1', limit=limit)

        return jsonify({
            'success': True,
            'techniques': techniques,
            'total': len(techniques)
        }), 200

    except Exception as e:
        logger.error(f"Error searching techniques: {e}")
        return jsonify({'error': 'Internal error'}), 500


@bp.route('/mitre/techniques/<technique_id>', methods=['GET'])
@login_required
def get_technique(technique_id):
    """Detalle de una técnica MITRE"""
    try:
        from app.services.mitre_service import get_mitre_service
        svc = get_mitre_service()

        technique = svc.get_technique(technique_id)
        return jsonify({
            'success': True,
            'technique': technique
        }), 200

    except Exception as e:
        logger.error(f"Error getting technique: {e}")
        return jsonify({'error': 'Internal error'}), 500


@bp.route('/mitre/tactics', methods=['GET'])
@login_required
def list_tactics():
    """Lista de tácticas MITRE ATT&CK"""
    try:
        from app.services.mitre_service import get_mitre_service
        svc = get_mitre_service()

        tactics = svc.get_all_tactics()
        return jsonify({
            'success': True,
            'tactics': tactics
        }), 200

    except Exception as e:
        logger.error(f"Error listing tactics: {e}")
        return jsonify({'error': 'Internal error'}), 500


@bp.route('/mitre/malware/<malware_name>', methods=['GET'])
@login_required
def techniques_by_malware(malware_name):
    """Técnicas asociadas a una familia de malware"""
    try:
        from app.services.mitre_service import get_mitre_service
        svc = get_mitre_service()

        technique_ids = svc.get_techniques_for_malware(malware_name)
        techniques = [svc.get_technique(tid) for tid in technique_ids]

        return jsonify({
            'success': True,
            'malware': malware_name,
            'techniques': techniques,
            'total': len(techniques)
        }), 200

    except Exception as e:
        logger.error(f"Error getting malware techniques: {e}")
        return jsonify({'error': 'Internal error'}), 500


@bp.route('/mitre/stats', methods=['GET'])
@login_required
def mitre_stats():
    """Estadísticas del dataset MITRE"""
    try:
        from app.services.mitre_service import get_mitre_service
        svc = get_mitre_service()

        stats = svc.get_stats()
        return jsonify({
            'success': True,
            'stats': stats
        }), 200

    except Exception as e:
        logger.error(f"Error getting MITRE stats: {e}")
        return jsonify({'error': 'Internal error'}), 500


@bp.route('/mitre/update', methods=['POST'])
@login_required
def update_mitre():
    """Actualizar datos MITRE desde API oficial (solo admin)"""
    try:
        if current_user.role != 'admin':
            return jsonify({'error': 'Solo administradores pueden actualizar MITRE'}), 403

        from app.services.mitre_service import get_mitre_service
        svc = get_mitre_service()

        result = svc.update_from_stix()
        status = 200 if result.get('success') else 500
        return jsonify(result), status

    except Exception as e:
        logger.error(f"Error updating MITRE: {e}")
        return jsonify({'error': 'Internal error'}), 500


# =============================================================================
# STIX 2.1 EXPORT ENDPOINTS
# =============================================================================

@bp.route('/stix/analysis/<int:analysis_id>', methods=['GET'])
@login_required
def export_analysis_stix(analysis_id):
    """Exporta un análisis como STIX 2.1 Bundle"""
    try:
        from app.services.stix_exporter import STIXExporter
        exporter = STIXExporter()

        bundle = exporter.export_analysis(analysis_id)

        if 'error' in bundle:
            return jsonify(bundle), 404

        # Retornar como JSON con Content-Type STIX
        download = request.args.get('download', 'false').lower() == 'true'
        response = Response(
            json.dumps(bundle, indent=2, default=str),
            mimetype='application/stix+json;version=2.1'
        )

        if download:
            response.headers['Content-Disposition'] = (
                f'attachment; filename=analysis_{analysis_id}_stix.json'
            )

        return response

    except Exception as e:
        logger.error(f"Error exporting STIX: {e}")
        return jsonify({'error': 'Internal error'}), 500


@bp.route('/stix/incident/<int:incident_id>', methods=['GET'])
@login_required
def export_incident_stix(incident_id):
    """Exporta un incidente como STIX 2.1 Bundle"""
    try:
        from app.services.stix_exporter import STIXExporter
        exporter = STIXExporter()

        bundle = exporter.export_incident(incident_id)

        if 'error' in bundle:
            return jsonify(bundle), 404

        download = request.args.get('download', 'false').lower() == 'true'
        response = Response(
            json.dumps(bundle, indent=2, default=str),
            mimetype='application/stix+json;version=2.1'
        )

        if download:
            response.headers['Content-Disposition'] = (
                f'attachment; filename=incident_{incident_id}_stix.json'
            )

        return response

    except Exception as e:
        logger.error(f"Error exporting incident STIX: {e}")
        return jsonify({'error': 'Internal error'}), 500


@bp.route('/stix/bulk', methods=['POST'])
@login_required
def export_bulk_stix():
    """Exporta múltiples IOCs como STIX Bundle"""
    try:
        data = request.get_json()
        if not data or 'ioc_ids' not in data:
            return jsonify({'error': 'ioc_ids requeridos'}), 400

        from app.services.stix_exporter import STIXExporter
        exporter = STIXExporter()

        bundle = exporter.export_iocs_bulk(data['ioc_ids'])

        return Response(
            json.dumps(bundle, indent=2, default=str),
            mimetype='application/stix+json;version=2.1'
        )

    except Exception as e:
        logger.error(f"Error exporting bulk STIX: {e}")
        return jsonify({'error': 'Internal error'}), 500
