"""
Rutas API v2 - SOC Agent v5
Febrero 2025

CAMBIOS v5:
- Eliminadas IPQualityScore y Censys
- Agregadas: Criminal IP, Pulsedive, URLScan, MalwareBazaar
- Modelos LLM actualizados: grok-2-latest, llama-3.1-70b-versatile, gemini-2.0-flash
"""
from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from app.services.llm_orchestrator import LLMOrchestrator
from app.services.session_manager import SessionManager
from app.models.ioc import IOC, IOCAnalysis, db
from app.utils.validators import validate_ioc, sanitize_chat_input
from app.schemas.api import AnalyzeRequest, ChatMessageRequest
from app.schemas.validator import validate_request
from app import limiter
import logging
from datetime import datetime
from functools import wraps

logger = logging.getLogger(__name__)

bp = Blueprint('api_v2', __name__, url_prefix='/api/v2')


def require_json(f):
    """Valida que el request tenga Content-Type application/json"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ('POST', 'PUT') and not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 415
        return f(*args, **kwargs)
    return decorated


def safe_error_response(error: Exception, context: str = ""):
    """Retorna error sin exponer detalles internos en producción"""
    logger.error(f"{context}: {error}", exc_info=True)
    if current_app.debug:
        return jsonify({'error': str(error)}), 500
    return jsonify({'error': 'An internal error occurred'}), 500

_orchestrator = None
_session_manager = None


def get_orchestrator():
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = LLMOrchestrator()
    return _orchestrator


def get_session_manager():
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager


# =============================================================================
# ANÁLISIS
# =============================================================================

@bp.route('/analyze/enhanced', methods=['POST'])
@login_required
@limiter.limit("30 per hour")
@limiter.limit("5 per minute")
@validate_request(AnalyzeRequest)
def analyze_enhanced(data: AnalyzeRequest):
    """Análisis mejorado con LLM Orchestrator y caché inteligente"""
    try:
        ioc_value = data.ioc
        ioc_type = data.type.value if data.type else None
        user_context = data.context
        use_llm_planning = data.use_llm_planning
        session_id = data.session_id
        force_refresh = data.force_refresh

        if not ioc_type:
            from app.utils.validators import detect_ioc_type
            ioc_type = detect_ioc_type(ioc_value)
            if not ioc_type:
                return jsonify({'error': 'No se pudo detectar tipo de IOC'}), 400

        # === CACHE CHECK ===
        if not force_refresh:
            from app.services.ioc_cache import get_cached_analysis
            cached = get_cached_analysis(ioc_value, ioc_type)
            if cached:
                # Si hay sesion, vincular el IOC existente
                if session_id:
                    try:
                        sm = get_session_manager()
                        ioc_obj = IOC.query.filter_by(value=ioc_value, ioc_type=ioc_type).first()
                        if ioc_obj:
                            sm.add_ioc_to_session(
                                session_id=session_id,
                                ioc_id=ioc_obj.id,
                                analysis_id=cached['analysis_id'],
                                role='analyzed'
                            )
                            db.session.commit()
                    except Exception as e:
                        logger.error(f"Error linking cached IOC to session: {e}")

                return jsonify({
                    'success': True,
                    'cached': True,
                    'cache_age_minutes': cached['cache_age_minutes'],
                    'analysis_id': cached['analysis_id'],
                    'ioc': cached['ioc'],
                    'type': cached['type'],
                    'confidence_score': cached['confidence_score'],
                    'risk_level': cached['risk_level'],
                    'llm_analysis': cached.get('llm_analysis'),
                    'sources_used': cached.get('sources_used', []),
                    'api_results': cached.get('api_results', {}),
                    'mitre_techniques': cached.get('mitre_techniques', []),
                    'processing_time': cached.get('processing_time', 0),
                    'session_id': session_id,
                    'timestamp': cached.get('timestamp')
                }), 200

        # === FRESH ANALYSIS ===
        orch = get_orchestrator()
        sm = get_session_manager()

        session_context = sm.build_context_for_llm(session_id) if session_id else None

        analysis_result = orch.analyze_with_intelligence(
            ioc=ioc_value,
            ioc_type=ioc_type,
            user_context=user_context,
            use_llm_planning=use_llm_planning,
            session_context=session_context
        )

        # Guardar en BD
        ioc_obj = IOC.query.filter_by(value=ioc_value, ioc_type=ioc_type).first()
        if not ioc_obj:
            ioc_obj = IOC(value=ioc_value, ioc_type=ioc_type, first_seen=datetime.utcnow(), times_analyzed=0)
            db.session.add(ioc_obj)
            db.session.flush()

        ioc_obj.last_analyzed = datetime.utcnow()
        ioc_obj.times_analyzed += 1

        analysis = IOCAnalysis(
            ioc_id=ioc_obj.id,
            user_id=current_user.id,
            confidence_score=analysis_result['confidence_score'],
            risk_level=analysis_result['risk_level'],
            recommendation=analysis_result.get('llm_analysis', {}).get('recommendations', []),
            virustotal_data=analysis_result['api_results'].get('virustotal'),
            abuseipdb_data=analysis_result['api_results'].get('abuseipdb'),
            shodan_data=analysis_result['api_results'].get('shodan'),
            otx_data=analysis_result['api_results'].get('otx'),
            greynoise_data=analysis_result['api_results'].get('greynoise'),
            threatfox_data=analysis_result['api_results'].get('threatfox'),
            urlhaus_data=analysis_result['api_results'].get('urlhaus'),
            malwarebazaar_data=analysis_result['api_results'].get('malwarebazaar'),
            google_safebrowsing_data=analysis_result['api_results'].get('google_safebrowsing'),
            securitytrails_data=analysis_result['api_results'].get('securitytrails'),
            hybrid_analysis_data=analysis_result['api_results'].get('hybrid_analysis'),
            criminal_ip_data=analysis_result['api_results'].get('criminal_ip'),
            pulsedive_data=analysis_result['api_results'].get('pulsedive'),
            urlscan_data=analysis_result['api_results'].get('urlscan'),
            shodan_internetdb_data=analysis_result['api_results'].get('shodan_internetdb'),
            ip_api_data=analysis_result['api_results'].get('ip_api'),
            llm_analysis=analysis_result.get('llm_analysis'),
            mitre_techniques=analysis_result.get('mitre_techniques', []),
            sources_used=analysis_result.get('sources_used', []),
            processing_time=analysis_result['processing_time']
        )
        db.session.add(analysis)
        db.session.flush()

        if session_id:
            try:
                sm.add_ioc_to_session(session_id=session_id, ioc_id=ioc_obj.id, analysis_id=analysis.id,
                                      role='analyzed')
            except Exception as e:
                logger.error(f"Error adding IOC to session: {e}")

        db.session.commit()

        return jsonify({
            'success': True,
            'analysis_id': analysis.id,
            'ioc': ioc_value,
            'type': ioc_type,
            'confidence_score': analysis_result['confidence_score'],
            'risk_level': analysis_result['risk_level'],
            'llm_analysis': analysis_result.get('llm_analysis'),
            'sources_used': analysis_result.get('sources_used', []),
            'api_results': analysis_result['api_results'],
            'mitre_techniques': analysis_result.get('mitre_techniques', []),
            'processing_time': analysis_result['processing_time'],
            'session_id': session_id,
            'timestamp': analysis_result['timestamp']
        }), 200

    except Exception as e:
        db.session.rollback()
        return safe_error_response(e, "Enhanced analysis error")


# =============================================================================
# CHAT
# =============================================================================

@bp.route('/chat/message', methods=['POST'])
@login_required
@limiter.limit("60 per hour")
@limiter.limit("10 per minute")
@validate_request(ChatMessageRequest)
def chat_message(data: ChatMessageRequest):
    """Chat interactivo con soporte de sesiones"""
    try:
        # Sanitizar input del chat (doble capa: Pydantic + sanitize)
        message, was_truncated = sanitize_chat_input(data.message)
        if not message:
            return jsonify({'error': 'Mensaje vacío o inválido'}), 400

        session_id = data.session_id
        llm_provider = data.llm_provider
        history = data.history

        orch = get_orchestrator()
        result = orch.chat_analysis(
            message=message,
            user_id=current_user.id,
            session_id=session_id,
            conversation_history=history,
            preferred_provider=llm_provider
        )

        return jsonify({
            'success': True,
            'response': result['response'],
            'requires_analysis': result.get('requires_analysis', False),
            'analysis_data': result.get('analysis_data'),
            'session_id': result.get('session_id'),
            'session_title': result.get('session_title'),
            'llm_provider': result.get('llm_provider'),
            'timestamp': datetime.utcnow().isoformat()
        }), 200

    except Exception as e:
        return safe_error_response(e, "Chat error")


# =============================================================================
# SESIONES
# =============================================================================

@bp.route('/sessions', methods=['GET'])
@login_required
def list_sessions():
    try:
        sm = get_session_manager()
        limit = request.args.get('limit', 20, type=int)
        status = request.args.get('status')  # None = todas
        sessions = sm.get_user_sessions(user_id=current_user.id, limit=limit, status=status)
        return jsonify({'success': True, 'sessions': [s.to_dict() for s in sessions], 'total': len(sessions)}), 200
    except Exception as e:
        return safe_error_response(e, "List sessions error")


@bp.route('/sessions/active', methods=['GET'])
@login_required
def get_active_session():
    try:
        sm = get_session_manager()
        session = sm.get_active_session(current_user.id)
        return jsonify(
            {'success': True, 'session': session.to_dict() if session else None, 'has_active': bool(session)}), 200
    except Exception as e:
        return safe_error_response(e, "Get active session error")


@bp.route('/sessions', methods=['POST'])
@login_required
@require_json
def create_session():
    try:
        data = request.get_json() or {}
        sm = get_session_manager()
        close_existing = data.get('close_existing', False)
        session = sm.create_new_session(
            user_id=current_user.id,
            title=data.get('title'),
            close_existing=close_existing
        )
        return jsonify({'success': True, 'session': session.to_dict()}), 201
    except Exception as e:
        return safe_error_response(e, "Create session error")


@bp.route('/sessions/<int:session_id>', methods=['GET'])
@login_required
def get_session(session_id):
    try:
        sm = get_session_manager()
        session = sm.get_session(session_id)
        if not session:
            return jsonify({'error': 'Sesión no encontrada'}), 404
        if session.user_id != current_user.id and current_user.role != 'admin':
            return jsonify({'error': 'No autorizado'}), 403
        return jsonify({'success': True, 'session': session.to_dict()}), 200
    except Exception as e:
        return safe_error_response(e, "Get session error")


@bp.route('/sessions/<int:session_id>', methods=['PUT', 'PATCH'])
@login_required
@require_json
def update_session(session_id):
    try:
        data = request.get_json() or {}
        sm = get_session_manager()
        session = sm.get_session(session_id)
        if not session:
            return jsonify({'error': 'Sesión no encontrada'}), 404
        if session.user_id != current_user.id and current_user.role != 'admin':
            return jsonify({'error': 'No autorizado'}), 403
        updated = sm.update_session(session_id=session_id, title=data.get('title'),
                                    description=data.get('description'))
        return jsonify({'success': True, 'session': updated.to_dict()}), 200
    except Exception as e:
        return safe_error_response(e, "Update session error")


@bp.route('/sessions/<int:session_id>/close', methods=['POST'])
@login_required
def close_session(session_id):
    try:
        sm = get_session_manager()
        session = sm.get_session(session_id)
        if not session:
            return jsonify({'error': 'Sesión no encontrada'}), 404
        if session.user_id != current_user.id and current_user.role != 'admin':
            return jsonify({'error': 'No autorizado'}), 403
        closed = sm.close_session(session_id)
        if closed:
            session = sm.get_session(session_id)
            return jsonify({'success': True, 'session': session.to_dict() if session else {}}), 200
        return jsonify({'error': 'No se pudo cerrar la sesion'}), 500
    except Exception as e:
        return safe_error_response(e, "Close session error")


@bp.route('/sessions/<int:session_id>/messages', methods=['GET'])
@login_required
def get_session_messages(session_id):
    try:
        sm = get_session_manager()
        session = sm.get_session(session_id)
        if not session:
            return jsonify({'error': 'Sesión no encontrada'}), 404
        if session.user_id != current_user.id and current_user.role != 'admin':
            return jsonify({'error': 'No autorizado'}), 403
        limit = request.args.get('limit', 50, type=int)
        messages = sm.get_session_messages(session_id, limit=limit)
        return jsonify({'success': True, 'messages': [m.to_dict() for m in messages], 'total': len(messages)}), 200
    except Exception as e:
        return safe_error_response(e, "Get messages error")


@bp.route('/sessions/<int:session_id>/iocs', methods=['GET'])
@login_required
def get_session_iocs(session_id):
    try:
        sm = get_session_manager()
        session = sm.get_session(session_id)
        if not session:
            return jsonify({'error': 'Sesión no encontrada'}), 404
        if session.user_id != current_user.id and current_user.role != 'admin':
            return jsonify({'error': 'No autorizado'}), 403
        iocs = sm.get_session_iocs(session_id)
        return jsonify({'success': True, 'iocs': [i.to_dict() for i in iocs], 'total': len(iocs)}), 200
    except Exception as e:
        return safe_error_response(e, "Get IOCs error")


@bp.route('/sessions/<int:session_id>/export', methods=['GET'])
@login_required
def export_session(session_id):
    """Exporta una sesion en JSON, Markdown, PDF o DOCX"""
    try:
        from flask import Response, send_file
        sm = get_session_manager()
        session = sm.get_session(session_id)
        if not session:
            return jsonify({'error': 'Sesion no encontrada'}), 404
        if session.user_id != current_user.id and current_user.role != 'admin':
            return jsonify({'error': 'No autorizado'}), 403

        fmt = request.args.get('format', 'json').lower()
        messages = sm.get_session_messages(session_id, limit=500)
        iocs = sm.get_session_iocs(session_id)

        session_data = session.to_dict()
        messages_data = [m.to_dict() for m in messages]
        iocs_data = [i.to_dict() for i in iocs]

        if fmt == 'json':
            return jsonify({
                'session': session_data,
                'messages': messages_data,
                'iocs': iocs_data
            }), 200

        elif fmt == 'markdown':
            lines = []
            lines.append(f"# {session_data.get('title', 'Sesion de Investigacion')}")
            lines.append(f"**Fecha:** {session_data.get('created_at', 'N/A')}")
            lines.append(f"**Estado:** {session_data.get('status', 'N/A')}")
            lines.append(f"**Riesgo:** {session_data.get('highest_risk_level', 'N/A')}")
            lines.append("")

            if iocs_data:
                lines.append("## IOCs Analizados")
                lines.append("| IOC | Tipo | Riesgo | Score |")
                lines.append("|-----|------|--------|-------|")
                for ioc in iocs_data:
                    lines.append(f"| `{ioc.get('ioc_value', 'N/A')}` | {ioc.get('ioc_type', '')} | {ioc.get('risk_level', '')} | {ioc.get('confidence_score', '')} |")
                lines.append("")

            if messages_data:
                lines.append("## Conversacion")
                lines.append("")
                for msg in messages_data:
                    if msg.get('is_summary'):
                        continue
                    role_label = "Analista" if msg['role'] == 'user' else "SOC AI"
                    lines.append(f"### {role_label} ({msg.get('created_at', '')[:16]})")
                    lines.append(msg.get('content', ''))
                    lines.append("")

            md_content = "\n".join(lines)
            return Response(md_content, mimetype='text/markdown',
                          headers={'Content-Disposition': f'attachment; filename=session_{session_id}.md'})

        elif fmt == 'pdf':
            try:
                from app.services.report_generator import ReportGenerator
                rg = ReportGenerator()
                pdf_buffer = rg.generate_pdf(session_id)
                if pdf_buffer:
                    return send_file(pdf_buffer, mimetype='application/pdf',
                                   as_attachment=True, download_name=f'session_{session_id}.pdf')
                return jsonify({'error': 'Error generando PDF'}), 500
            except ImportError:
                return jsonify({'error': 'Generador de reportes no disponible'}), 500

        elif fmt == 'docx':
            try:
                from app.services.report_generator import ReportGenerator
                rg = ReportGenerator()
                docx_buffer = rg.generate_docx(session_id)
                if docx_buffer:
                    return send_file(docx_buffer,
                                   mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                                   as_attachment=True, download_name=f'session_{session_id}.docx')
                return jsonify({'error': 'Error generando DOCX'}), 500
            except ImportError:
                return jsonify({'error': 'Generador de reportes no disponible'}), 500

        else:
            return jsonify({'error': f'Formato no soportado: {fmt}. Validos: json, markdown, pdf, docx'}), 400

    except Exception as e:
        return safe_error_response(e, "Export session error")


# =============================================================================
# APIs STATUS (ACTUALIZADO v5)
# =============================================================================

@bp.route('/apis/status', methods=['GET'])
@login_required
def apis_status():
    """Estado de las APIs - ACTUALIZADO sin IPQualityScore/Censys"""
    try:
        from app.models.ioc import APIUsage
        from datetime import date

        today = date.today()
        apis = [
            'virustotal', 'abuseipdb', 'shodan', 'otx', 'greynoise',
            'urlhaus', 'threatfox', 'malwarebazaar',
            'google_safebrowsing', 'securitytrails', 'hybrid_analysis',
            'criminal_ip', 'pulsedive', 'urlscan',
            'shodan_internetdb', 'ip_api',
            'censys', 'ipinfo'
        ]

        api_key_map = {
            'virustotal': 'virustotal', 'abuseipdb': 'abuseipdb', 'shodan': 'shodan',
            'otx': 'otx', 'greynoise': 'greynoise',
            'urlhaus': 'abusech_auth', 'threatfox': 'abusech_auth', 'malwarebazaar': 'abusech_auth',
            'google_safebrowsing': 'google_safebrowsing', 'securitytrails': 'securitytrails',
            'hybrid_analysis': 'hybrid_analysis',
            'criminal_ip': 'criminal_ip', 'pulsedive': 'pulsedive', 'urlscan': 'urlscan',
            'shodan_internetdb': None, 'ip_api': None,
            'censys': 'censys', 'ipinfo': 'ipinfo'
        }

        status = {}
        for api_name in apis:
            usage = APIUsage.query.filter_by(api_name=api_name, date=today).first()
            limit = current_app.config.get('API_LIMITS', {}).get(api_name, 1000)

            if api_name in ['shodan_internetdb', 'ip_api']:
                limit = 'unlimited'

            requests_count = usage.requests_count if usage else 0
            errors_count = usage.errors_count if usage else 0

            if limit == 'unlimited':
                health, usage_percent, remaining = 'healthy', 0, 'unlimited'
            else:
                if requests_count >= limit:
                    health = 'limit_reached'
                elif requests_count > limit * 0.8:
                    health = 'warning'
                elif errors_count > requests_count * 0.5 and requests_count > 0:
                    health = 'degraded'
                else:
                    health = 'healthy'
                usage_percent = round((requests_count / limit) * 100, 2) if limit > 0 else 0
                remaining = max(0, limit - requests_count)

            key_name = api_key_map.get(api_name)
            is_configured = True if key_name is None else bool(current_app.config['API_KEYS'].get(key_name))

            status[api_name] = {
                'requests_today': requests_count,
                'errors_today': errors_count,
                'daily_limit': limit,
                'remaining': remaining,
                'usage_percent': usage_percent,
                'health': health,
                'is_configured': is_configured
            }

        return jsonify({
            'success': True,
            'apis': status,
            'total_apis': len(apis),
            'healthy_apis': len([a for a in status.values() if a['health'] == 'healthy']),
            'configured_apis': len([a for a in status.values() if a['is_configured']])
        }), 200

    except Exception as e:
        return safe_error_response(e, "API status error")


@bp.route('/llm/providers', methods=['GET'])
@login_required
def llm_providers():
    """Proveedores LLM - MODELOS ACTUALIZADOS"""
    try:
        api_keys = current_app.config.get('API_KEYS', {})

        providers = {
            'xai': {
                'available': bool(api_keys.get('xai')),
                'model': 'grok-3-mini',
                'description': 'Muy rápido, excelente razonamiento',
                'speed': 'very_fast',
                'cost': 'paid'
            },
            'openai': {
                'available': bool(api_keys.get('openai')),
                'model': 'gpt-4o-mini',
                'description': 'Alta calidad, rápido y económico',
                'speed': 'fast',
                'cost': 'paid'
            },
            'groq': {
                'available': bool(api_keys.get('groq')),
                'model': 'llama-3.3-70b-versatile',
                'description': 'Extremadamente rápido y gratuito',
                'speed': 'very_fast',
                'cost': 'free'
            },
            'gemini': {
                'available': bool(api_keys.get('gemini')),
                'model': 'gemini-2.5-flash',
                'description': 'Gratuito con buen contexto largo',
                'speed': 'medium',
                'cost': 'free'
            }
        }

        default_provider = next((p for p in ['xai', 'openai', 'groq', 'gemini'] if providers[p]['available']), None)

        return jsonify({
            'success': True,
            'providers': providers,
            'default_provider': default_provider
        }), 200

    except Exception as e:
        return safe_error_response(e, "LLM providers error")


@bp.route('/llm/test', methods=['POST'])
@login_required
@require_json
def test_llm():
    """Probar un proveedor LLM"""
    try:
        data = request.get_json() or {}
        provider = data.get('provider')

        if not provider:
            return jsonify({'error': 'Provider requerido'}), 400

        api_keys = current_app.config.get('API_KEYS', {})
        if not api_keys.get(provider):
            return jsonify({'error': f'{provider} no configurado'}), 400

        from app.services.llm_service import LLMService
        import time

        llm = LLMService(provider=provider)
        start = time.time()

        if provider == 'gemini':
            result = llm._call_gemini("Responde 'OK' si funciona")
        else:
            result = llm._call_generic_openai_style("Responde 'OK' si funciona")

        elapsed = time.time() - start

        return jsonify({
            'success': 'error' not in result,
            'provider': provider,
            'response_time_ms': round(elapsed * 1000, 2),
            'result': result
        }), 200

    except Exception as e:
        return safe_error_response(e, "LLM test error")


@bp.route('/apis/<api_name>/test', methods=['POST'])
@login_required
@require_json
def test_api(api_name):
    """Probar una API de threat intelligence"""
    try:
        orch = get_orchestrator()
        data = request.get_json() or {}
        test_ioc = data.get('test_ioc', '8.8.8.8')

        if api_name not in orch.api_clients:
            return jsonify({'error': f'API {api_name} no disponible'}), 404

        client = orch.api_clients[api_name]

        if api_name in ['greynoise', 'abuseipdb', 'criminal_ip', 'shodan_internetdb', 'shodan', 'virustotal', 'otx', 'censys', 'ipinfo']:
            result = client.check_ip(test_ioc)
        elif api_name == 'ip_api':
            result = client.get_geolocation(test_ioc)
        elif api_name in ['urlhaus']:
            result = client.check_url(f"http://{test_ioc}")
        elif api_name == 'google_safebrowsing':
            result = client.check_url(f"http://{test_ioc}")
        elif api_name == 'threatfox':
            result = client.search_ioc(test_ioc)
        elif api_name == 'pulsedive':
            result = client.get_indicator(test_ioc)
        elif api_name == 'urlscan':
            result = client.search(f"ip:{test_ioc}")
        elif api_name == 'malwarebazaar':
            result = client.query_hash('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f')
        elif api_name == 'hybrid_analysis':
            result = client.search_hash('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f')
        elif api_name == 'securitytrails':
            result = client.get_domain_details('google.com')
        else:
            result = {'error': 'Test no implementado'}

        return jsonify({
            'success': 'error' not in result,
            'api': api_name,
            'test_ioc': test_ioc,
            'result': result
        }), 200

    except Exception as e:
        return safe_error_response(e, "API test error")


@bp.route('/health', methods=['GET'])
def health_check():
    """Verificación de salud"""
    try:
        from app import db
        db.session.execute(db.text('SELECT 1'))
        db_status = 'healthy'
    except Exception as e:
        logger.error(f"Health check DB error: {e}")
        db_status = 'error'

    api_keys = current_app.config.get('API_KEYS', {})
    configured_apis = sum(1 for v in api_keys.values() if v)
    llm_count = sum(1 for p in ['xai', 'openai', 'groq', 'gemini'] if api_keys.get(p))

    return jsonify({
        'status': 'healthy' if db_status == 'healthy' else 'degraded',
        'database': db_status,
        'configured_apis': configured_apis,
        'available_llms': llm_count,
        'version': '5.0',
        'timestamp': datetime.utcnow().isoformat()
    }), 200