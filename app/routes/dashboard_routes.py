"""
Dashboard Routes - SOC Agent Fase 3
Endpoints para estadísticas y visualizaciones
"""
from flask import Blueprint, request, jsonify, render_template
from flask_login import login_required, current_user
from app.services.dashboard_stats import DashboardStatsService
import logging

logger = logging.getLogger(__name__)

bp = Blueprint('dashboard', __name__, url_prefix='/dashboard')

_stats_service = None


def get_stats_service():
    global _stats_service
    if _stats_service is None:
        _stats_service = DashboardStatsService()
    return _stats_service


# =============================================================================
# PÁGINA PRINCIPAL DEL DASHBOARD
# =============================================================================

@bp.route('/')
@login_required
def index():
    """Renderiza la página del dashboard"""
    return render_template('dashboard.html')


# =============================================================================
# API ENDPOINTS PARA ESTADÍSTICAS
# =============================================================================

@bp.route('/api/stats', methods=['GET'])
@login_required
def get_all_stats():
    """
    Obtiene todas las estadísticas del dashboard
    
    Query params:
    - days: Período en días (default: 30)
    - user_only: Solo datos del usuario actual (default: false)
    """
    try:
        days = request.args.get('days', 30, type=int)
        user_only = request.args.get('user_only', 'false').lower() == 'true'
        
        user_id = current_user.id if user_only else None
        
        service = get_stats_service()
        stats = service.get_all_stats(user_id=user_id, days=days)
        
        return jsonify({
            'success': True,
            'stats': stats,
            'period_days': days,
            'user_filtered': user_only
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/stats/risk', methods=['GET'])
@login_required
def get_risk_distribution():
    """Distribución de niveles de riesgo"""
    try:
        days = request.args.get('days', 30, type=int)
        user_only = request.args.get('user_only', 'false').lower() == 'true'
        user_id = current_user.id if user_only else None
        
        service = get_stats_service()
        data = service.get_risk_distribution(user_id=user_id, days=days)
        
        return jsonify({'success': True, 'data': data}), 200
        
    except Exception as e:
        logger.error(f"Error getting risk distribution: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/stats/apis', methods=['GET'])
@login_required
def get_api_usage():
    """Estadísticas de uso de APIs"""
    try:
        days = request.args.get('days', 30, type=int)
        
        service = get_stats_service()
        data = service.get_api_usage_stats(days=days)
        
        return jsonify({'success': True, 'data': data}), 200
        
    except Exception as e:
        logger.error(f"Error getting API usage: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/stats/timeline', methods=['GET'])
@login_required
def get_timeline():
    """Timeline de análisis"""
    try:
        days = request.args.get('days', 30, type=int)
        user_only = request.args.get('user_only', 'false').lower() == 'true'
        user_id = current_user.id if user_only else None
        
        service = get_stats_service()
        data = service.get_analysis_timeline(user_id=user_id, days=days)
        
        return jsonify({'success': True, 'data': data}), 200
        
    except Exception as e:
        logger.error(f"Error getting timeline: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/stats/geo', methods=['GET'])
@login_required
def get_geo_threats():
    """Amenazas por ubicación geográfica"""
    try:
        days = request.args.get('days', 30, type=int)
        user_only = request.args.get('user_only', 'false').lower() == 'true'
        user_id = current_user.id if user_only else None
        
        service = get_stats_service()
        data = service.get_geo_threats(user_id=user_id, days=days)
        
        return jsonify({'success': True, 'data': data}), 200
        
    except Exception as e:
        logger.error(f"Error getting geo threats: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/stats/summary', methods=['GET'])
@login_required
def get_summary():
    """Resumen de estadísticas para cards"""
    try:
        days = request.args.get('days', 30, type=int)
        user_only = request.args.get('user_only', 'false').lower() == 'true'
        user_id = current_user.id if user_only else None
        
        service = get_stats_service()
        data = service.get_summary_stats(user_id=user_id, days=days)
        
        return jsonify({'success': True, 'data': data}), 200
        
    except Exception as e:
        logger.error(f"Error getting summary: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/stats/recent', methods=['GET'])
@login_required
def get_recent():
    """Análisis recientes"""
    try:
        limit = request.args.get('limit', 10, type=int)
        user_only = request.args.get('user_only', 'false').lower() == 'true'
        user_id = current_user.id if user_only else None
        
        service = get_stats_service()
        data = service.get_recent_analyses(user_id=user_id, limit=limit)
        
        return jsonify({'success': True, 'data': data}), 200
        
    except Exception as e:
        logger.error(f"Error getting recent analyses: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/stats/threats', methods=['GET'])
@login_required
def get_threats():
    """Top amenazas"""
    try:
        days = request.args.get('days', 30, type=int)
        user_only = request.args.get('user_only', 'false').lower() == 'true'
        user_id = current_user.id if user_only else None
        
        service = get_stats_service()
        data = service.get_top_threats(user_id=user_id, days=days)
        
        return jsonify({'success': True, 'data': data}), 200
        
    except Exception as e:
        logger.error(f"Error getting top threats: {e}")
        return jsonify({'error': str(e)}), 500
