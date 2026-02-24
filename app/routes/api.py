"""
API REST para análisis de IOCs
"""
from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from app.services.threat_intel import ThreatIntelService
from app.models.ioc import IOC, IOCAnalysis, Incident
from app.utils.validators import validate_ioc, detect_ioc_type
from app.utils.formatters import format_analysis_response
from app import db, limiter
from datetime import datetime
import time

api_bp = Blueprint('api', __name__)


@api_bp.route('/analyze', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def analyze_ioc():
    """
    Analiza un IOC
    ---
    Request Body:
    {
        "ioc": "8.8.8.8",
        "type": "ip"  # opcional, se detecta automáticamente
    }
    """
    data = request.get_json()

    if not data or 'ioc' not in data:
        return jsonify({'error': 'IOC requerido'}), 400

    ioc_value = data['ioc'].strip()
    ioc_type = data.get('type')

    # Validar IOC
    if not ioc_type:
        ioc_type = detect_ioc_type(ioc_value)
        if not ioc_type:
            return jsonify({'error': 'Tipo de IOC no válido o no detectado'}), 400

    is_valid, error_msg = validate_ioc(ioc_value, ioc_type)
    if not is_valid:
        return jsonify({'error': error_msg or f'IOC no válido para tipo {ioc_type}'}), 400

    # Verificar si existe en whitelist
    ioc_record = IOC.query.filter_by(value=ioc_value, ioc_type=ioc_type).first()
    if ioc_record and ioc_record.is_whitelisted:
        return jsonify({
            'message': 'IOC en whitelist',
            'ioc': ioc_value,
            'type': ioc_type,
            'whitelisted': True,
            'reason': ioc_record.whitelist_reason
        }), 200

    # Realizar análisis
    start_time = time.time()

    try:
        service = ThreatIntelService()
        results = service.analyze_ioc(ioc_value, ioc_type)

        processing_time = time.time() - start_time

        # Guardar en base de datos
        if not ioc_record:
            ioc_record = IOC(value=ioc_value, ioc_type=ioc_type)
            db.session.add(ioc_record)
            db.session.flush()
        else:
            ioc_record.last_analyzed = datetime.utcnow()
            ioc_record.times_analyzed += 1

        # Crear registro de análisis
        analysis = IOCAnalysis(
            ioc_id=ioc_record.id,
            user_id=current_user.id,
            confidence_score=results['confidence_score'],
            risk_level=results['risk_level'],
            recommendation=results['recommendation'],
            virustotal_data=results.get('virustotal') or results.get('api_results', {}).get('virustotal'),
            abuseipdb_data=results.get('abuseipdb') or results.get('api_results', {}).get('abuseipdb'),
            shodan_data=results.get('shodan') or results.get('api_results', {}).get('shodan'),
            otx_data=results.get('otx') or results.get('api_results', {}).get('otx'),
            llm_analysis=results.get('llm_analysis'),
            mitre_techniques=results.get('mitre_techniques'),
            errors=results.get('errors'),
            processing_time=processing_time
        )

        db.session.add(analysis)
        db.session.commit()

        # Crear incidente si es crítico o alto
        if results['confidence_score'] >= 50:
            ticket_id = f"SOC-{datetime.now().strftime('%Y%m%d')}-{analysis.id:05d}"
            severity = "P1" if results['confidence_score'] >= 70 else "P2"

            incident = Incident(
                ticket_id=ticket_id,
                title=f"Detección {results['risk_level']}: {ioc_type.upper()} {ioc_value}",
                description=results['recommendation'],
                severity=severity,
                status='open',
                analysis_id=analysis.id,
                created_by=current_user.id
            )
            db.session.add(incident)
            db.session.commit()

            results['incident'] = {
                'ticket_id': ticket_id,
                'severity': severity
            }

        # Formatear respuesta
        response = format_analysis_response(results, analysis.id)

        return jsonify(response), 200

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error analyzing IOC: {e}")
        return jsonify({'error': f'Error en análisis: {str(e)}'}), 500


@api_bp.route('/bulk-analyze', methods=['POST'])
@login_required
@limiter.limit("2 per minute")
def bulk_analyze():
    """
    Analiza múltiples IOCs
    ---
    Request Body:
    {
        "iocs": [
            {"value": "8.8.8.8", "type": "ip"},
            {"value": "malicious.com", "type": "domain"}
        ]
    }
    """
    data = request.get_json()

    if not data or 'iocs' not in data:
        return jsonify({'error': 'Lista de IOCs requerida'}), 400

    iocs = data['iocs']

    if not isinstance(iocs, list):
        return jsonify({'error': 'IOCs debe ser una lista'}), 400

    if len(iocs) > 10:
        return jsonify({'error': 'Máximo 10 IOCs por solicitud'}), 400

    results = []
    service = ThreatIntelService()

    for ioc_data in iocs:
        if not isinstance(ioc_data, dict) or 'value' not in ioc_data:
            continue

        ioc_value = ioc_data['value'].strip()
        ioc_type = ioc_data.get('type') or detect_ioc_type(ioc_value)

        if not ioc_type:
            results.append({
                'ioc': ioc_value,
                'error': 'Tipo de IOC no detectado'
            })
            continue

        is_valid, error_msg = validate_ioc(ioc_value, ioc_type)
        if not is_valid:
            results.append({
                'ioc': ioc_value,
                'error': error_msg or 'IOC no válido'
            })
            continue

        try:
            analysis = service.analyze_ioc(ioc_value, ioc_type)
            results.append({
                'ioc': ioc_value,
                'type': ioc_type,
                'confidence_score': analysis['confidence_score'],
                'risk_level': analysis['risk_level']
            })

            # Pequeña pausa entre análisis
            time.sleep(0.5)

        except Exception as e:
            results.append({
                'ioc': ioc_value,
                'error': str(e)
            })

    return jsonify({
        'total': len(iocs),
        'analyzed': len([r for r in results if 'error' not in r]),
        'results': results
    }), 200


@api_bp.route('/analysis/<int:analysis_id>', methods=['GET'])
@login_required
def get_analysis(analysis_id):
    """Obtiene un análisis específico"""
    analysis = IOCAnalysis.query.get_or_404(analysis_id)
    return jsonify(analysis.to_dict()), 200


@api_bp.route('/ioc/<int:ioc_id>', methods=['GET'])
@login_required
def get_ioc(ioc_id):
    """Obtiene información de un IOC"""
    ioc = IOC.query.get_or_404(ioc_id)

    # Incluir análisis recientes
    recent_analyses = IOCAnalysis.query.filter_by(
        ioc_id=ioc.id
    ).order_by(IOCAnalysis.created_at.desc()).limit(5).all()

    data = ioc.to_dict()
    data['recent_analyses'] = [a.to_dict(include_details=False) for a in recent_analyses]

    return jsonify(data), 200


@api_bp.route('/ioc/<int:ioc_id>/whitelist', methods=['POST'])
@login_required
def whitelist_ioc(ioc_id):
    """Agrega un IOC a la whitelist"""
    if current_user.role not in ['admin', 'analyst']:
        return jsonify({'error': 'Permisos insuficientes'}), 403

    ioc = IOC.query.get_or_404(ioc_id)
    data = request.get_json()

    reason = data.get('reason', 'Sin razón especificada')

    ioc.is_whitelisted = True
    ioc.whitelist_reason = reason

    db.session.commit()

    return jsonify({
        'message': 'IOC agregado a whitelist',
        'ioc': ioc.to_dict()
    }), 200


@api_bp.route('/ioc/<int:ioc_id>/whitelist', methods=['DELETE'])
@login_required
def remove_from_whitelist(ioc_id):
    """Remueve un IOC de la whitelist"""
    if current_user.role not in ['admin', 'analyst']:
        return jsonify({'error': 'Permisos insuficientes'}), 403

    ioc = IOC.query.get_or_404(ioc_id)

    ioc.is_whitelisted = False
    ioc.whitelist_reason = None

    db.session.commit()

    return jsonify({
        'message': 'IOC removido de whitelist',
        'ioc': ioc.to_dict()
    }), 200


@api_bp.route('/stats', methods=['GET'])
@login_required
def get_stats():
    """Estadísticas generales del sistema"""
    from app.models.ioc import APIUsage
    from datetime import timedelta

    today = datetime.utcnow().date()
    week_ago = today - timedelta(days=7)

    stats = {
        'analyses': {
            'total': IOCAnalysis.query.count(),
            'today': IOCAnalysis.query.filter(
                db.func.date(IOCAnalysis.created_at) == today
            ).count(),
            'week': IOCAnalysis.query.filter(
                IOCAnalysis.created_at >= week_ago
            ).count()
        },
        'iocs': {
            'total': IOC.query.count(),
            'whitelisted': IOC.query.filter_by(is_whitelisted=True).count()
        },
        'risk_distribution': {
            'critical': IOCAnalysis.query.filter_by(risk_level='CRÍTICO').count(),
            'high': IOCAnalysis.query.filter_by(risk_level='ALTO').count(),
            'medium': IOCAnalysis.query.filter_by(risk_level='MEDIO').count(),
            'low': IOCAnalysis.query.filter_by(risk_level='BAJO').count(),
            'clean': IOCAnalysis.query.filter_by(risk_level='LIMPIO').count()
        },
        'incidents': {
            'open': Incident.query.filter_by(status='open').count(),
            'total': Incident.query.count()
        }
    }

    # API usage
    today_usage = APIUsage.query.filter_by(date=today).all()
    stats['api_usage'] = {}

    for usage in today_usage:
        limit = current_app.config['API_LIMITS'].get(usage.api_name, 0)
        stats['api_usage'][usage.api_name] = {
            'used': usage.requests_count,
            'limit': limit,
            'remaining': limit - usage.requests_count,
            'errors': usage.errors_count
        }

    return jsonify(stats), 200


@api_bp.route('/incident/<int:incident_id>/update', methods=['PATCH'])
@login_required
def update_incident(incident_id):
    """Actualiza un incidente"""
    if current_user.role not in ['admin', 'analyst']:
        return jsonify({'error': 'Permisos insuficientes'}), 403

    incident = Incident.query.get_or_404(incident_id)
    data = request.get_json()

    # Actualizar campos permitidos
    if 'status' in data:
        incident.status = data['status']
        if data['status'] in ['resolved', 'closed']:
            incident.resolved_at = datetime.utcnow()

    if 'notes' in data:
        incident.notes = data['notes']

    if 'assigned_to' in data:
        incident.assigned_to = data['assigned_to']

    incident.updated_at = datetime.utcnow()

    db.session.commit()

    return jsonify({
        'message': 'Incidente actualizado',
        'incident': incident.to_dict()
    }), 200