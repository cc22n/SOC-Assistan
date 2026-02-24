"""
Dashboard Statistics Service
SOC Agent - Fase 3

Proporciona estadísticas y datos para visualizaciones del dashboard:
- Distribución de risk levels
- Uso de APIs
- Timeline de análisis
- Mapa de amenazas por país
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from sqlalchemy import func, desc, and_
from flask import current_app

logger = logging.getLogger(__name__)


class DashboardStatsService:
    """Servicio de estadísticas para el dashboard"""

    def __init__(self):
        pass

    def get_all_stats(self, user_id: int = None, days: int = 30) -> Dict:
        """
        Obtiene todas las estadísticas para el dashboard

        Args:
            user_id: Filtrar por usuario (None = todos)
            days: Días hacia atrás para estadísticas
        """
        return {
            'risk_distribution': self.get_risk_distribution(user_id, days),
            'api_usage': self.get_api_usage_stats(days),
            'timeline': self.get_analysis_timeline(user_id, days),
            'geo_threats': self.get_geo_threats(user_id, days),
            'summary': self.get_summary_stats(user_id, days),
            'recent_analyses': self.get_recent_analyses(user_id, limit=10),
            'top_threats': self.get_top_threats(user_id, days),
        }

    def get_risk_distribution(self, user_id: int = None, days: int = 30) -> Dict:
        """
        Distribución de análisis por nivel de riesgo
        Para gráfico de pie/donut
        """
        try:
            from app.models.ioc import IOCAnalysis
            from app import db

            since = datetime.utcnow() - timedelta(days=days)

            query = db.session.query(
                IOCAnalysis.risk_level,
                func.count(IOCAnalysis.id).label('count')
            ).filter(IOCAnalysis.created_at >= since)

            if user_id:
                query = query.filter(IOCAnalysis.user_id == user_id)

            results = query.group_by(IOCAnalysis.risk_level).all()

            # Mapear a formato para Chart.js
            risk_colors = {
                'CRÍTICO': '#dc2626',  # red-600
                'ALTO': '#ea580c',  # orange-600
                'MEDIO': '#ca8a04',  # yellow-600
                'BAJO': '#16a34a',  # green-600
                'LIMPIO': '#0284c7',  # sky-600
            }

            labels = []
            data = []
            colors = []

            for risk_level, count in results:
                if risk_level:
                    labels.append(risk_level)
                    data.append(count)
                    colors.append(risk_colors.get(risk_level, '#6b7280'))

            return {
                'labels': labels,
                'data': data,
                'colors': colors,
                'total': sum(data)
            }

        except Exception as e:
            logger.error(f"Error getting risk distribution: {e}")
            return {'labels': [], 'data': [], 'colors': [], 'total': 0}

    def get_api_usage_stats(self, days: int = 30) -> Dict:
        """
        Estadísticas de uso de APIs
        Para gráfico de barras
        """
        try:
            from app.models.ioc import APIUsage
            from app import db

            since = datetime.utcnow().date() - timedelta(days=days)

            # Agregado por API
            total_req_col = func.sum(APIUsage.requests_count).label('total_requests')
            total_err_col = func.sum(APIUsage.errors_count).label('total_errors')

            results = db.session.query(
                APIUsage.api_name,
                total_req_col,
                total_err_col
            ).filter(
                APIUsage.date >= since
            ).group_by(
                APIUsage.api_name
            ).order_by(
                total_req_col.desc()
            ).all()

            labels = []
            requests = []
            errors = []
            success_rate = []

            for api_name, total_req, total_err in results:
                labels.append(api_name)
                requests.append(total_req or 0)
                errors.append(total_err or 0)

                if total_req and total_req > 0:
                    rate = ((total_req - (total_err or 0)) / total_req) * 100
                else:
                    rate = 100
                success_rate.append(round(rate, 1))

            return {
                'labels': labels,
                'requests': requests,
                'errors': errors,
                'success_rate': success_rate
            }

        except Exception as e:
            logger.error(f"Error getting API usage stats: {e}")
            return {'labels': [], 'requests': [], 'errors': [], 'success_rate': []}

    def get_analysis_timeline(self, user_id: int = None, days: int = 30) -> Dict:
        """
        Timeline de análisis por día
        Para gráfico de líneas
        """
        try:
            from app.models.ioc import IOCAnalysis
            from app import db

            since = datetime.utcnow() - timedelta(days=days)

            query = db.session.query(
                func.date(IOCAnalysis.created_at).label('date'),
                func.count(IOCAnalysis.id).label('count'),
                IOCAnalysis.risk_level
            ).filter(IOCAnalysis.created_at >= since)

            if user_id:
                query = query.filter(IOCAnalysis.user_id == user_id)

            results = query.group_by(
                func.date(IOCAnalysis.created_at),
                IOCAnalysis.risk_level
            ).order_by('date').all()

            # Organizar por fecha
            dates = {}
            for date, count, risk_level in results:
                date_str = date.isoformat() if hasattr(date, 'isoformat') else str(date)
                if date_str not in dates:
                    dates[date_str] = {
                        'total': 0,
                        'CRÍTICO': 0,
                        'ALTO': 0,
                        'MEDIO': 0,
                        'BAJO': 0,
                        'LIMPIO': 0
                    }
                dates[date_str]['total'] += count
                if risk_level:
                    dates[date_str][risk_level] = count

            # Convertir a arrays para Chart.js
            sorted_dates = sorted(dates.keys())

            return {
                'labels': sorted_dates,
                'datasets': {
                    'total': [dates[d]['total'] for d in sorted_dates],
                    'critico': [dates[d]['CRÍTICO'] for d in sorted_dates],
                    'alto': [dates[d]['ALTO'] for d in sorted_dates],
                    'medio': [dates[d]['MEDIO'] for d in sorted_dates],
                    'bajo': [dates[d]['BAJO'] for d in sorted_dates],
                    'limpio': [dates[d]['LIMPIO'] for d in sorted_dates],
                }
            }

        except Exception as e:
            logger.error(f"Error getting analysis timeline: {e}")
            return {'labels': [], 'datasets': {}}

    def get_geo_threats(self, user_id: int = None, days: int = 30) -> Dict:
        """
        Amenazas geolocalizadas por país
        Para mapa de calor
        """
        try:
            from app.models.ioc import IOCAnalysis, IOC
            from app import db

            since = datetime.utcnow() - timedelta(days=days)

            # Buscar en ip_api_data y criminal_ip_data
            # Incluir TODOS los niveles de riesgo que tengan geodata
            query = db.session.query(IOCAnalysis).filter(
                IOCAnalysis.created_at >= since
            )

            if user_id:
                query = query.filter(IOCAnalysis.user_id == user_id)

            analyses = query.limit(500).all()

            countries = {}
            markers = []

            for analysis in analyses:
                country = None
                lat = None
                lon = None
                city = None

                # Intentar obtener de ip_api_data
                if analysis.ip_api_data and isinstance(analysis.ip_api_data, dict):
                    country = analysis.ip_api_data.get('country')
                    lat = analysis.ip_api_data.get('lat')
                    lon = analysis.ip_api_data.get('lon')
                    city = analysis.ip_api_data.get('city')

                # Si no, intentar de ipinfo_data (v3.1)
                elif analysis.ipinfo_data and isinstance(analysis.ipinfo_data, dict):
                    country = analysis.ipinfo_data.get('country')
                    city = analysis.ipinfo_data.get('city')
                    loc = analysis.ipinfo_data.get('loc')
                    if loc and ',' in str(loc):
                        try:
                            parts = str(loc).split(',')
                            lat = float(parts[0])
                            lon = float(parts[1])
                        except (ValueError, IndexError):
                            pass

                # Si no, intentar de criminal_ip_data
                elif analysis.criminal_ip_data and isinstance(analysis.criminal_ip_data, dict):
                    country = analysis.criminal_ip_data.get('country')
                    city = analysis.criminal_ip_data.get('city')

                # Si no, de shodan_data
                elif analysis.shodan_data and isinstance(analysis.shodan_data, dict):
                    country = analysis.shodan_data.get('country')
                    city = analysis.shodan_data.get('city')

                # Si no, de abuseipdb_data
                elif analysis.abuseipdb_data and isinstance(analysis.abuseipdb_data, dict):
                    country = analysis.abuseipdb_data.get('country_code')

                if country:
                    if country not in countries:
                        countries[country] = {'count': 0, 'critical': 0, 'high': 0, 'medium': 0}

                    countries[country]['count'] += 1
                    if analysis.risk_level == 'CRÍTICO':
                        countries[country]['critical'] += 1
                    elif analysis.risk_level == 'ALTO':
                        countries[country]['high'] += 1
                    elif analysis.risk_level == 'MEDIO':
                        countries[country]['medium'] += 1

                    # Agregar marcador si tenemos coordenadas
                    if lat and lon and analysis.ioc:
                        markers.append({
                            'lat': lat,
                            'lon': lon,
                            'ioc': analysis.ioc.value,
                            'risk': analysis.risk_level,
                            'country': country,
                            'city': city
                        })

            # Top 10 países
            sorted_countries = sorted(
                countries.items(),
                key=lambda x: x[1]['count'],
                reverse=True
            )[:10]

            return {
                'countries': {k: v for k, v in sorted_countries},
                'markers': markers[:100],  # Limitar marcadores
                'total_countries': len(countries)
            }

        except Exception as e:
            logger.error(f"Error getting geo threats: {e}")
            return {'countries': {}, 'markers': [], 'total_countries': 0}

    def get_summary_stats(self, user_id: int = None, days: int = 30) -> Dict:
        """
        Estadísticas resumen para cards del dashboard
        """
        try:
            from app.models.ioc import IOCAnalysis, IOC, Incident
            from app.models.session import InvestigationSession
            from app import db

            since = datetime.utcnow() - timedelta(days=days)

            # Total análisis
            analysis_query = db.session.query(func.count(IOCAnalysis.id)).filter(
                IOCAnalysis.created_at >= since
            )
            if user_id:
                analysis_query = analysis_query.filter(IOCAnalysis.user_id == user_id)
            total_analyses = analysis_query.scalar() or 0

            # Análisis críticos
            critical_query = db.session.query(func.count(IOCAnalysis.id)).filter(
                IOCAnalysis.created_at >= since,
                IOCAnalysis.risk_level == 'CRÍTICO'
            )
            if user_id:
                critical_query = critical_query.filter(IOCAnalysis.user_id == user_id)
            critical_count = critical_query.scalar() or 0

            # IOCs únicos
            ioc_query = db.session.query(func.count(func.distinct(IOCAnalysis.ioc_id))).filter(
                IOCAnalysis.created_at >= since
            )
            if user_id:
                ioc_query = ioc_query.filter(IOCAnalysis.user_id == user_id)
            unique_iocs = ioc_query.scalar() or 0

            # Sesiones activas
            try:
                session_query = db.session.query(func.count(InvestigationSession.id)).filter(
                    InvestigationSession.status == 'active'
                )
                if user_id:
                    session_query = session_query.filter(InvestigationSession.user_id == user_id)
                active_sessions = session_query.scalar() or 0
            except:
                active_sessions = 0

            # Incidentes abiertos
            try:
                incident_query = db.session.query(func.count(Incident.id)).filter(
                    Incident.status.in_(['open', 'investigating'])
                )
                open_incidents = incident_query.scalar() or 0
            except:
                open_incidents = 0

            # Promedio de score
            avg_query = db.session.query(func.avg(IOCAnalysis.confidence_score)).filter(
                IOCAnalysis.created_at >= since
            )
            if user_id:
                avg_query = avg_query.filter(IOCAnalysis.user_id == user_id)
            avg_score = avg_query.scalar() or 0

            return {
                'total_analyses': total_analyses,
                'critical_count': critical_count,
                'unique_iocs': unique_iocs,
                'active_sessions': active_sessions,
                'open_incidents': open_incidents,
                'avg_confidence': round(avg_score, 1),
                'period_days': days
            }

        except Exception as e:
            logger.error(f"Error getting summary stats: {e}")
            return {
                'total_analyses': 0,
                'critical_count': 0,
                'unique_iocs': 0,
                'active_sessions': 0,
                'open_incidents': 0,
                'avg_confidence': 0,
                'period_days': days
            }

    def get_recent_analyses(self, user_id: int = None, limit: int = 10) -> List[Dict]:
        """
        Análisis más recientes
        """
        try:
            from app.models.ioc import IOCAnalysis
            from app import db

            query = db.session.query(IOCAnalysis).order_by(
                IOCAnalysis.created_at.desc()
            )

            if user_id:
                query = query.filter(IOCAnalysis.user_id == user_id)

            analyses = query.limit(limit).all()

            return [
                {
                    'id': a.id,
                    'ioc': a.ioc.value if a.ioc else 'N/A',
                    'ioc_type': a.ioc.ioc_type if a.ioc else 'N/A',
                    'risk_level': a.risk_level,
                    'confidence': a.confidence_score,
                    'sources': len(a.sources_used) if a.sources_used else 0,
                    'created_at': a.created_at.isoformat() if a.created_at else None
                }
                for a in analyses
            ]

        except Exception as e:
            logger.error(f"Error getting recent analyses: {e}")
            return []

    def get_top_threats(self, user_id: int = None, days: int = 30) -> List[Dict]:
        """
        Top amenazas detectadas
        """
        try:
            from app.models.ioc import IOCAnalysis
            from app import db

            since = datetime.utcnow() - timedelta(days=days)

            query = db.session.query(IOCAnalysis).filter(
                IOCAnalysis.created_at >= since,
                IOCAnalysis.risk_level.in_(['CRÍTICO', 'ALTO'])
            ).order_by(
                IOCAnalysis.confidence_score.desc()
            )

            if user_id:
                query = query.filter(IOCAnalysis.user_id == user_id)

            analyses = query.limit(5).all()

            return [
                {
                    'id': a.id,
                    'ioc': a.ioc.value if a.ioc else 'N/A',
                    'ioc_type': a.ioc.ioc_type if a.ioc else 'N/A',
                    'risk_level': a.risk_level,
                    'confidence': a.confidence_score,
                    'summary': a.llm_analysis.get('executive_summary', '')[:100] if a.llm_analysis else ''
                }
                for a in analyses
            ]

        except Exception as e:
            logger.error(f"Error getting top threats: {e}")
            return []
