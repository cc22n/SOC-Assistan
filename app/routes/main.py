"""
Rutas principales de la aplicación
"""
from flask import (
    Blueprint,
    render_template,
    request,
    jsonify,
    current_app
)
from flask_login import login_required, current_user
from datetime import datetime, timedelta

from app.services.threat_intel import ThreatIntelService
from app.models.ioc import IOC, IOCAnalysis, Incident, APIUsage
from app import db, cache

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def index():
    """Página principal"""
    return render_template('index.html')


@main_bp.route('/dashboard')
@login_required
def dashboard():
    """Dashboard del analista SOC"""
    today = datetime.utcnow().date()
    week_ago = today - timedelta(days=7)

    stats = {
        'total_analyses': IOCAnalysis.query.count(),
        'today_analyses': IOCAnalysis.query.filter(
            db.func.date(IOCAnalysis.created_at) == today
        ).count(),
        'week_analyses': IOCAnalysis.query.filter(
            IOCAnalysis.created_at >= week_ago
        ).count(),
        'critical_iocs': IOCAnalysis.query.filter(
            IOCAnalysis.risk_level.in_(['CRÍTICO', 'CRITICO'])
        ).count(),
        'high_risk_iocs': IOCAnalysis.query.filter(
            IOCAnalysis.risk_level == 'ALTO'
        ).count(),
        'open_incidents': Incident.query.filter_by(status='open').count(),
        'unique_iocs': IOC.query.count()
    }

    recent_analyses = IOCAnalysis.query.order_by(
        IOCAnalysis.created_at.desc()
    ).limit(10).all()

    open_incidents = Incident.query.filter_by(
        status='open'
    ).order_by(
        Incident.created_at.desc()
    ).limit(5).all()

    return render_template(
        'dashboard.html',
        stats=stats,
        recent_analyses=recent_analyses,
        open_incidents=open_incidents
    )


@main_bp.route('/analyze')
@login_required
def analyze_page():
    """Página de análisis de IOCs"""
    return render_template('analysis.html')


@main_bp.route('/history')
@login_required
def history():
    """Historial de análisis"""
    page = request.args.get('page', 1, type=int)
    per_page = 20

    risk_level = request.args.get('risk_level')
    ioc_type = request.args.get('ioc_type')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')

    query = IOCAnalysis.query

    if risk_level:
        query = query.filter_by(risk_level=risk_level)

    if ioc_type:
        query = query.join(IOC).filter(IOC.ioc_type == ioc_type)

    if date_from:
        try:
            date_from = datetime.fromisoformat(date_from)
            query = query.filter(IOCAnalysis.created_at >= date_from)
        except ValueError:
            pass

    if date_to:
        try:
            date_to = datetime.fromisoformat(date_to)
            query = query.filter(IOCAnalysis.created_at <= date_to)
        except ValueError:
            pass

    pagination = query.order_by(
        IOCAnalysis.created_at.desc()
    ).paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )

    return render_template(
        'history.html',
        analyses=pagination.items,
        pagination=pagination
    )


@main_bp.route('/incidents')
@login_required
def incidents():
    """Lista de incidentes"""
    page = request.args.get('page', 1, type=int)
    per_page = 20

    status = request.args.get('status', 'open')

    query = Incident.query
    if status:
        query = query.filter_by(status=status)

    pagination = query.order_by(
        Incident.created_at.desc()
    ).paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )

    return render_template(
        'incidents.html',
        incidents=pagination.items,
        pagination=pagination
    )


@main_bp.route('/incident/<int:incident_id>')
@login_required
def incident_detail(incident_id):
    """Detalle de un incidente"""
    incident = Incident.query.get_or_404(incident_id)
    return render_template(
        'incident_detail.html',
        incident=incident
    )


@main_bp.route('/api-stats')
@login_required
def api_stats():
    """Estadísticas de uso de APIs"""
    today = datetime.utcnow().date()

    today_usage = APIUsage.query.filter_by(date=today).all()

    usage_data = {}

    for usage in today_usage:
        limit = current_app.config['API_LIMITS'].get(usage.api_name, 0)

        if isinstance(limit, str):  # 'unlimited'
            usage_data[usage.api_name] = {
                'used': usage.requests_count,
                'errors': usage.errors_count,
                'limit': limit,
                'remaining': 'unlimited'
            }
        else:
            limit = int(limit)
            usage_data[usage.api_name] = {
                'used': usage.requests_count,
                'errors': usage.errors_count,
                'limit': limit,
                'remaining': max(limit - usage.requests_count, 0)
            }

    for api_name, limit in current_app.config['API_LIMITS'].items():
        if api_name not in usage_data:
            usage_data[api_name] = {
                'used': 0,
                'errors': 0,
                'limit': limit,
                'remaining': 'unlimited' if isinstance(limit, str) else limit
            }

    return render_template(
        'api_stats.html',
        usage=usage_data
    )


@main_bp.route('/search')
@login_required
def search():
    """Búsqueda de IOCs"""
    query_text = request.args.get('q', '').strip()

    if not query_text:
        return render_template('search.html', results=None)

    iocs = IOC.query.filter(
        IOC.value.contains(query_text)
    ).limit(50).all()

    analyses = IOCAnalysis.query.join(IOC).filter(
        IOC.value.contains(query_text)
    ).order_by(
        IOCAnalysis.created_at.desc()
    ).limit(20).all()

    return render_template(
        'search.html',
        query=query_text,
        iocs=iocs,
        analyses=analyses
    )


@main_bp.route('/about')
def about():
    """Acerca de"""
    return render_template('about.html')

@main_bp.route('/chat')
@login_required
def chat():
    """Chat interactivo SOC"""
    return render_template('chat.html')
