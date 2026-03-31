from app.models.session import InvestigationSession, SessionIOC, SessionMessage
# ============================================
# app/models/__init__.py
# ============================================
"""
Modelos de la aplicación
"""
from app.models.ioc import User, IOC, IOCAnalysis, Incident, APIUsage
from app.models.audit import AuditEvent
from app.models.mitre import (
    MITRE_TECHNIQUES_DB,
    MALWARE_TO_TECHNIQUES,
    get_technique_info,
    get_techniques_by_malware
)

__all__ = [
    'User',
    'IOC',
    'IOCAnalysis',
    'Incident',
    'APIUsage',
    'AuditEvent',
    'MITRE_TECHNIQUES_DB',
    'MALWARE_TO_TECHNIQUES',
    'get_technique_info',
    'get_techniques_by_malware'
]


# ============================================
# app/routes/__init__.py
# ============================================
"""
Blueprints de rutas
"""
from app.routes.main import main_bp
from app.routes.api import api_bp
from app.routes.auth import auth_bp

__all__ = ['main_bp', 'api_bp', 'auth_bp']


# ============================================
# app/services/__init__.py
# ============================================
"""
Servicios de la aplicación
"""
from app.services.threat_intel import ThreatIntelService
from app.services.llm_service import LLMService
from app.services.api_clients import (
    VirusTotalClient,
    AbuseIPDBClient,
    ShodanClient,
    OTXClient
)

__all__ = [
    'ThreatIntelService',
    'LLMService',
    'VirusTotalClient',
    'AbuseIPDBClient',
    'ShodanClient',
    'OTXClient'
]


# ============================================
# app/utils/__init__.py
# ============================================
"""
Utilidades
"""
from app.utils.validators import (
    is_valid_ip,
    is_valid_hash,
    is_valid_domain,
    is_valid_url,
    detect_ioc_type,
    validate_ioc,
    extract_iocs_from_text
)
from app.utils.formatters import (
    format_analysis_response,
    format_incident_ticket,
    format_summary_report
)

__all__ = [
    'is_valid_ip',
    'is_valid_hash',
    'is_valid_domain',
    'is_valid_url',
    'detect_ioc_type',
    'validate_ioc',
    'extract_iocs_from_text',
    'format_analysis_response',
    'format_incident_ticket',
    'format_summary_report'
]