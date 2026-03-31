"""
IOC Cache Service - Cache inteligente para analisis de IOCs
SOC Agent v1

Evita llamadas repetidas a APIs de threat intelligence si el mismo IOC
fue analizado recientemente. Respeta rate limits y ahorra tiempo.

Estrategia:
- Cache en base de datos (IOCAnalysis ya existente)
- TTL configurable por nivel de riesgo
- IOCs criticos: cache corto (1 hora) - pueden cambiar rapido
- IOCs limpios: cache largo (24 horas) - poco probable que cambien
- Forzar re-analisis disponible via parametro
"""
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from app.models.ioc import IOC, IOCAnalysis
from app import db

logger = logging.getLogger(__name__)

# TTL por nivel de riesgo (en horas)
CACHE_TTL_BY_RISK = {
    'CRÍTICO': 1,
    'CRITICO': 1,
    'ALTO': 3,
    'MEDIO': 6,
    'BAJO': 12,
    'LIMPIO': 24,
}

# TTL por tipo de IOC (en horas)
# IPs y URLs cambian rápido; hashes son inmutables; dominios son intermedios
CACHE_TTL_BY_TYPE = {
    'ip':     1,    # Reputación de IP puede cambiar en horas
    'url':    1,    # URLs maliciosas se dan de baja rápido
    'domain': 6,    # Dominios cambian más lentamente
    'hash':   24,   # Hashes son inmutables
}

# Alias legacy para backwards compatibility
CACHE_TTL = CACHE_TTL_BY_RISK

DEFAULT_TTL_HOURS = 6


def _get_effective_ttl(risk_level: str, ioc_type: str) -> int:
    """
    Retorna el TTL efectivo en horas para una combinación de riesgo + tipo de IOC.
    Usa el mínimo entre ambos para mayor seguridad (frescura de datos).
    """
    ttl_risk = CACHE_TTL_BY_RISK.get(risk_level, DEFAULT_TTL_HOURS)
    ttl_type = CACHE_TTL_BY_TYPE.get(ioc_type, DEFAULT_TTL_HOURS)
    return min(ttl_risk, ttl_type)


def get_cached_analysis(
    ioc_value: str,
    ioc_type: str = None,
    max_age_hours: int = None,
    force_refresh: bool = False
) -> Optional[Dict[str, Any]]:
    """
    Busca un analisis reciente en cache para el IOC dado.

    Args:
        ioc_value: Valor del IOC (IP, dominio, hash, URL)
        ioc_type: Tipo del IOC (opcional, para filtrar)
        max_age_hours: Edad maxima del cache en horas (None = usar TTL por riesgo)
        force_refresh: Si True, ignorar cache y forzar re-analisis

    Returns:
        Dict con datos del analisis cacheado, o None si no hay cache valido
    """
    if force_refresh:
        logger.info(f"Cache bypass requested for {ioc_value}")
        return None

    try:
        # Buscar el IOC en BD
        query = IOC.query.filter_by(value=ioc_value)
        if ioc_type:
            query = query.filter_by(ioc_type=ioc_type)
        ioc = query.first()

        if not ioc:
            return None

        # Buscar el analisis mas reciente
        analysis = IOCAnalysis.query.filter_by(
            ioc_id=ioc.id
        ).order_by(
            IOCAnalysis.created_at.desc()
        ).first()

        if not analysis:
            return None

        # Calcular TTL (mínimo entre TTL-por-riesgo y TTL-por-tipo)
        if max_age_hours is not None:
            ttl_hours = max_age_hours
        else:
            ttl_hours = _get_effective_ttl(analysis.risk_level, ioc.ioc_type)

        # Verificar si el cache sigue vigente
        cache_expiry = analysis.created_at + timedelta(hours=ttl_hours)
        if datetime.utcnow() > cache_expiry:
            age = datetime.utcnow() - analysis.created_at
            logger.info(
                f"Cache expired for {ioc_value} "
                f"(age: {age.total_seconds()/3600:.1f}h, ttl: {ttl_hours}h)"
            )
            return None

        age = datetime.utcnow() - analysis.created_at
        logger.info(
            f"Cache HIT for {ioc_value} "
            f"(age: {age.total_seconds()/3600:.1f}h, ttl: {ttl_hours}h, "
            f"risk: {analysis.risk_level})"
        )

        # Reconstruir respuesta desde la BD
        cached_result = {
            'cached': True,
            'cache_age_minutes': int(age.total_seconds() / 60),
            'analysis_id': analysis.id,
            'ioc': ioc.value,
            'type': ioc.ioc_type,
            'confidence_score': analysis.confidence_score,
            'risk_level': analysis.risk_level,
            'sources_used': analysis.sources_used or [],
            'mitre_techniques': analysis.mitre_techniques or [],
            'processing_time': analysis.processing_time or 0,
            'timestamp': analysis.created_at.isoformat(),
            'llm_analysis': analysis.llm_analysis,
            'api_results': _rebuild_api_results(analysis),
        }

        return cached_result

    except Exception as e:
        logger.error(f"Cache lookup error for {ioc_value}: {e}")
        return None


def _rebuild_api_results(analysis: IOCAnalysis) -> Dict[str, Any]:
    """Reconstruye el dict de resultados de APIs desde los campos de la BD"""
    results = {}

    api_fields = {
        'virustotal': 'virustotal_data',
        'abuseipdb': 'abuseipdb_data',
        'shodan': 'shodan_data',
        'otx': 'otx_data',
        'greynoise': 'greynoise_data',
        'threatfox': 'threatfox_data',
        'urlhaus': 'urlhaus_data',
        'malwarebazaar': 'malwarebazaar_data',
        'google_safebrowsing': 'google_safebrowsing_data',
        'securitytrails': 'securitytrails_data',
        'hybrid_analysis': 'hybrid_analysis_data',
        'criminal_ip': 'criminal_ip_data',
        'pulsedive': 'pulsedive_data',
        'urlscan': 'urlscan_data',
        'shodan_internetdb': 'shodan_internetdb_data',
        'ip_api': 'ip_api_data',
    }

    for api_name, field_name in api_fields.items():
        data = getattr(analysis, field_name, None)
        if data:
            results[api_name] = data

    return results


def get_cache_stats() -> Dict[str, Any]:
    """Retorna estadisticas del cache para el dashboard"""
    try:
        from sqlalchemy import func

        now = datetime.utcnow()
        one_hour = now - timedelta(hours=1)
        one_day = now - timedelta(hours=24)

        total = IOCAnalysis.query.count()
        last_hour = IOCAnalysis.query.filter(IOCAnalysis.created_at >= one_hour).count()
        last_day = IOCAnalysis.query.filter(IOCAnalysis.created_at >= one_day).count()

        # IOCs unicos con cache vigente (estimado)
        active_cache = IOCAnalysis.query.filter(
            IOCAnalysis.created_at >= now - timedelta(hours=DEFAULT_TTL_HOURS)
        ).distinct(IOCAnalysis.ioc_id).count()

        return {
            'total_analyses': total,
            'last_hour': last_hour,
            'last_24h': last_day,
            'active_cached_iocs': active_cache,
        }

    except Exception as e:
        logger.error(f"Cache stats error: {e}")
        return {'total_analyses': 0, 'last_hour': 0, 'last_24h': 0, 'active_cached_iocs': 0}
