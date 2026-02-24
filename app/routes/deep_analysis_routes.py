"""
Deep Analysis Routes - SOC Agent
Endpoints para análisis profundo de IOCs
"""
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from app.services.deep_analysis_service import DeepAnalysisService
from app.utils.validators import validate_ioc, detect_ioc_type
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

bp = Blueprint('deep_analysis', __name__, url_prefix='/api/v2/deep')

_deep_service = None


def get_deep_service():
    global _deep_service
    if _deep_service is None:
        _deep_service = DeepAnalysisService()
    return _deep_service


@bp.route('/analyze', methods=['POST'])
@login_required
def deep_analyze():
    """
    Ejecuta análisis profundo de un IOC.
    
    POST /api/v2/deep/analyze
    Body:
    {
        "ioc": "45.142.212.100",
        "type": "ip",  // opcional, se auto-detecta
        "session_id": 123,  // opcional, para correlación
        "modules": {  // opcional, todos true por defecto
            "web_search": true,
            "correlation": true,
            "apt_analysis": true,
            "hypothesis": true
        }
    }
    
    Returns:
    {
        "success": true,
        "ioc": "45.142.212.100",
        "deep_analysis": {
            "base_analysis": {...},
            "web_search": {...},
            "correlations": {...},
            "apt_analysis": {...},
            "hypothesis": {...},
            "final_report": {...}
        },
        "processing_time": 12.5
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'ioc' not in data:
            return jsonify({'error': 'IOC es requerido'}), 400
        
        ioc = data['ioc'].strip()
        ioc_type = data.get('type')
        session_id = data.get('session_id')
        modules = data.get('modules', {})
        
        # Auto-detectar tipo si no se proporciona
        if not ioc_type:
            ioc_type = detect_ioc_type(ioc)
            if not ioc_type:
                return jsonify({'error': 'No se pudo detectar el tipo de IOC'}), 400
        
        # Validar IOC
        is_valid, error_msg = validate_ioc(ioc, ioc_type)
        if not is_valid:
            return jsonify({'error': error_msg}), 400
        
        logger.info(f"🔍 Deep analysis requested for {ioc_type}: {ioc}")
        
        # Ejecutar análisis profundo
        service = get_deep_service()
        result = service.deep_analyze(
            ioc=ioc,
            ioc_type=ioc_type,
            user_id=current_user.id,
            session_id=session_id,
            include_web_search=modules.get('web_search', True),
            include_correlation=modules.get('correlation', True),
            include_apt_analysis=modules.get('apt_analysis', True),
            include_hypothesis=modules.get('hypothesis', True)
        )
        
        return jsonify({
            'success': True,
            'ioc': ioc,
            'ioc_type': ioc_type,
            'deep_analysis': result,
            'modules_executed': result.get('modules_executed', []),
            'processing_time': result.get('processing_time', 0),
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Deep analysis error: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/apt-database', methods=['GET'])
@login_required
def get_apt_database():
    """
    Obtiene la base de datos de APTs conocidos.
    
    GET /api/v2/deep/apt-database
    """
    try:
        service = get_deep_service()
        
        apt_list = []
        for apt_name, apt_info in service.apt_indicators.items():
            apt_list.append({
                'name': apt_name,
                'aliases': apt_info.get('aliases', []),
                'country': apt_info.get('country'),
                'targets': apt_info.get('targets', []),
                'tools': apt_info.get('tools', []),
                'ttps': apt_info.get('ttps', [])
            })
        
        return jsonify({
            'success': True,
            'apts': apt_list,
            'total': len(apt_list)
        }), 200
        
    except Exception as e:
        logger.error(f"APT database error: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/mitre-techniques', methods=['GET'])
@login_required
def get_mitre_techniques():
    """
    Obtiene el diccionario de técnicas MITRE ATT&CK.
    
    GET /api/v2/deep/mitre-techniques
    """
    try:
        service = get_deep_service()
        
        techniques = [
            {'id': tid, 'name': tname}
            for tid, tname in service.mitre_techniques.items()
        ]
        
        return jsonify({
            'success': True,
            'techniques': techniques,
            'total': len(techniques)
        }), 200
        
    except Exception as e:
        logger.error(f"MITRE techniques error: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/quick-apt-check', methods=['POST'])
@login_required
def quick_apt_check():
    """
    Verificación rápida de APT sin análisis completo.
    Busca solo en la base de conocimiento local.
    
    POST /api/v2/deep/quick-apt-check
    Body: {"ioc": "...", "context": "datos adicionales"}
    """
    try:
        data = request.get_json()
        
        if not data or 'ioc' not in data:
            return jsonify({'error': 'IOC es requerido'}), 400
        
        ioc = data['ioc'].strip()
        context = data.get('context', '')
        
        service = get_deep_service()
        
        # Búsqueda rápida en BD local
        search_str = f"{ioc} {context}".lower()
        matches = service._search_local_apt_db(ioc, search_str)
        
        return jsonify({
            'success': True,
            'ioc': ioc,
            'matches': matches,
            'has_matches': len(matches) > 0
        }), 200
        
    except Exception as e:
        logger.error(f"Quick APT check error: {e}")
        return jsonify({'error': str(e)}), 500
