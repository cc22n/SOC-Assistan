"""
Perfiles de investigación: validación, perfiles del sistema y siembra idempotente.

Los nombres de API NO están hardcodeados en la validación: se comprueban contra las columnas `*_data` del modelo
(`IOCAnalysis.api_source_names()`) y contra la tabla de compatibilidad del orquestador (`_is_api_compatible`).
Los perfiles del sistema SÍ listan APIs, pero un test comprueba que todas existen y son compatibles con su tipo,
así que añadir/quitar una API no deja un perfil roto sin que se note.
"""
from typing import Any, Dict, List, Optional, Tuple

from app import db
from app.models.ioc import IOCAnalysis
from app.models.profile import InvestigationProfile

IOC_TYPES = ('ip', 'domain', 'url', 'hash', 'cve')
MAX_NAME = 120
MAX_DESCRIPTION = 1000
MAX_PROFILES_PER_USER = 50

# Perfiles del sistema (inmutables por la API). Adaptados a las APIs reales de SOC Agent a partir de los 8 de SOC Forge.
SYSTEM_PROFILES: List[Dict[str, Any]] = [
    {'name': 'Hash: consulta rápida', 'ioc_type': 'hash', 'apis': ['virustotal', 'malwarebazaar'],
     'description': 'Comprobación rápida de un hash: motores antivirus y base de MalwareBazaar.'},
    {'name': 'Hash: malware completo', 'ioc_type': 'hash',
     'apis': ['virustotal', 'malwarebazaar', 'hybrid_analysis', 'threatfox', 'otx'],
     'description': 'Investigación completa de un hash: antivirus, sandbox, feeds de amenazas y pulsos de OTX.'},
    {'name': 'IP: reputación', 'ioc_type': 'ip', 'apis': ['abuseipdb', 'greynoise', 'criminal_ip'],
     'description': 'Reputación rápida de una IP: reportes de abuso, ruido de Internet y puntuación de riesgo.'},
    {'name': 'IP: infraestructura', 'ioc_type': 'ip',
     'apis': ['shodan', 'shodan_internetdb', 'censys', 'criminal_ip'],
     'description': 'Superficie expuesta de una IP: puertos, servicios y vulnerabilidades conocidas.'},
    {'name': 'IP: investigación completa', 'ioc_type': 'ip',
     'apis': ['abuseipdb', 'greynoise', 'shodan', 'virustotal', 'otx', 'criminal_ip', 'threatfox', 'pulsedive'],
     'description': 'Análisis exhaustivo de una IP con todas las fuentes de reputación y de amenazas.'},
    {'name': 'Dominio: investigación', 'ioc_type': 'domain',
     'apis': ['virustotal', 'securitytrails', 'otx', 'urlscan', 'google_safebrowsing', 'crtsh', 'threatfox'],
     'description': 'Dominio: reputación, DNS/WHOIS histórico, certificados, escaneos y listas de bloqueo.'},
    {'name': 'CVE: explotación rápida', 'ioc_type': 'cve', 'apis': ['cisa_kev', 'epss'],
     'description': '¿Se está explotando? Catálogo KEV de CISA y probabilidad de explotación (EPSS). Sin LLM-planificador y barata.'},
    {'name': 'CVE: investigación completa', 'ioc_type': 'cve', 'apis': ['cisa_kev', 'nvd', 'epss', 'exploitdb'],
     'description': 'CVE: explotación (KEV, EPSS), gravedad (NVD/CVSS) y exploits públicos (Exploit-DB).'},
    {'name': 'URL: phishing', 'ioc_type': 'url',
     'apis': ['virustotal', 'urlscan', 'google_safebrowsing', 'pulsedive'],
     'description': 'URL sospechosa de phishing o ingeniería social.'},
    {'name': 'URL: entrega de malware', 'ioc_type': 'url',
     'apis': ['urlhaus', 'virustotal', 'urlscan', 'threatfox'],
     'description': 'URL sospechosa de entregar una carga maliciosa.'},
]


def compatible_apis(ioc_type: str) -> List[str]:
    """APIs que existen (columna *_data) y que soportan ese tipo de IOC, derivado del código, sin lista fija."""
    from app.services.llm_orchestrator import LLMOrchestrator
    orch = LLMOrchestrator.__new__(LLMOrchestrator)       # _is_api_compatible es puro: no necesita clientes
    return [a for a in IOCAnalysis.api_source_names() if orch._is_api_compatible(a, ioc_type)]


def validate_profile_fields(name: Any, description: Any, ioc_type: Any, apis: Any,
                            llm_synthesis: Any = True) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """Devuelve (campos_limpios, errores). Si hay errores, campos_limpios es None."""
    errors: List[str] = []
    if not isinstance(name, str) or not name.strip():
        errors.append('name requerido')
    elif len(name.strip()) > MAX_NAME:
        errors.append(f'name demasiado largo (máx. {MAX_NAME})')
    if description is None:
        description = ''
    if not isinstance(description, str):
        errors.append('description debe ser texto')
    elif len(description) > MAX_DESCRIPTION:
        errors.append(f'description demasiado larga (máx. {MAX_DESCRIPTION})')
    if ioc_type not in IOC_TYPES:
        errors.append(f'ioc_type debe ser uno de {list(IOC_TYPES)}')
    if not isinstance(llm_synthesis, bool):
        errors.append('llm_synthesis debe ser booleano')

    clean_apis: List[str] = []
    if not isinstance(apis, list) or not apis:
        errors.append('apis requerido: lista no vacía')
    elif len(apis) > InvestigationProfile.MAX_APIS:
        errors.append(f'demasiadas APIs (máx. {InvestigationProfile.MAX_APIS})')
    elif not all(isinstance(a, str) for a in apis):
        errors.append('apis debe ser una lista de nombres')
    elif len(set(apis)) != len(apis):
        errors.append('apis tiene nombres repetidos')
    elif ioc_type in IOC_TYPES:
        ok = set(compatible_apis(ioc_type))
        malas = [a for a in apis if a not in ok]
        if malas:
            errors.append(f'APIs inexistentes o no compatibles con {ioc_type}: {malas}')
        clean_apis = list(apis)

    if errors:
        return None, errors
    return {'name': name.strip(), 'description': description.strip(), 'ioc_type': ioc_type,
            'apis': clean_apis, 'llm_synthesis': llm_synthesis}, []


def ensure_system_profiles(commit: bool = True) -> Dict[str, int]:
    """
    Crea los perfiles del sistema que falten (por nombre) y actualiza su definición si cambió en el código.
    Idempotente. Devuelve {'created': n, 'updated': n}. El llamador es dueño de la transacción si commit=False.
    """
    created = updated = 0
    for spec in SYSTEM_PROFILES:
        row = InvestigationProfile.query.filter(
            InvestigationProfile.owner_id.is_(None), InvestigationProfile.is_system.is_(True),
            db.func.lower(InvestigationProfile.name) == spec['name'].lower()).first()
        if row is None:
            db.session.add(InvestigationProfile(owner_id=None, is_system=True, llm_synthesis=True, **spec))
            created += 1
        elif (row.apis != spec['apis'] or row.ioc_type != spec['ioc_type'] or row.description != spec['description']
              or not row.is_system):
            row.apis, row.ioc_type, row.description, row.is_system = (
                spec['apis'], spec['ioc_type'], spec['description'], True)
            updated += 1
    if commit:
        db.session.commit()
    else:
        db.session.flush()
    return {'created': created, 'updated': updated}
