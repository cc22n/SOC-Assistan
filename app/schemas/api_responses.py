"""
SOC Agent - Pydantic Schemas para respuestas de APIs de Threat Intelligence
Fase 4 - T4A-04

Valida las respuestas de cada API externa antes de usarlas en el cálculo
de score. Protege contra:
- APIs comprometidas que devuelvan valores inesperados
- Cambios de schema silenciosos en APIs externas
- Valores out-of-range que corrompan el scoring

Uso:
    from app.schemas.api_responses import parse_virustotal, parse_abuseipdb

    vt_data = parse_virustotal(raw_dict)   # retorna VirusTotalResponse o None
    if vt_data:
        score += vt_data.malicious * 3
"""
import logging
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

logger = logging.getLogger(__name__)


# =============================================================================
# VIRUS TOTAL
# =============================================================================

class VirusTotalResponse(BaseModel):
    """Schema para respuesta de VirusTotal (IP, hash, dominio, URL)"""
    malicious: int = Field(0, ge=0, le=10000)
    suspicious: int = Field(0, ge=0, le=10000)
    harmless: int = Field(0, ge=0)
    undetected: int = Field(0, ge=0)
    reputation: int = Field(0)
    asn: Optional[int] = None
    as_owner: Optional[str] = Field(None, max_length=200)
    country: Optional[str] = Field(None, max_length=5)
    # Hash-specific
    found: Optional[bool] = None
    type_description: Optional[str] = Field(None, max_length=200)
    meaningful_name: Optional[str] = Field(None, max_length=200)

    @field_validator('country')
    @classmethod
    def valid_country(cls, v):
        if v and not v.isalpha():
            return None
        return v


# =============================================================================
# ABUSEIPDB
# =============================================================================

class AbuseIPDBResponse(BaseModel):
    """Schema para respuesta de AbuseIPDB"""
    abuse_confidence: int = Field(0, ge=0, le=100)
    total_reports: int = Field(0, ge=0)
    country_code: Optional[str] = Field(None, max_length=5)
    isp: Optional[str] = Field(None, max_length=200)
    domain: Optional[str] = Field(None, max_length=255)
    is_tor: bool = False
    is_public: bool = True

    @field_validator('country_code')
    @classmethod
    def valid_country(cls, v):
        if v and not v.isalpha():
            return None
        return v


# =============================================================================
# GREYNOISE
# =============================================================================

class GreyNoiseResponse(BaseModel):
    """Schema para respuesta de GreyNoise"""
    noise: bool = False
    riot: bool = False
    classification: Optional[str] = Field(None, max_length=50)
    name: Optional[str] = Field(None, max_length=200)
    link: Optional[str] = Field(None, max_length=500)
    message: Optional[str] = Field(None, max_length=200)

    @field_validator('classification')
    @classmethod
    def valid_classification(cls, v):
        allowed = {'malicious', 'benign', 'unknown', None}
        if v and v.lower() not in allowed:
            logger.warning(f"GreyNoise: unexpected classification value '{v}'")
            return 'unknown'
        return v.lower() if v else v


# =============================================================================
# SHODAN
# =============================================================================

class ShodanResponse(BaseModel):
    """Schema para respuesta de Shodan"""
    open_ports: List[int] = Field(default_factory=list, max_length=500)
    tags: List[str] = Field(default_factory=list, max_length=50)
    country_name: Optional[str] = Field(None, max_length=100)
    org: Optional[str] = Field(None, max_length=200)
    isp: Optional[str] = Field(None, max_length=200)
    os: Optional[str] = Field(None, max_length=100)
    vulns: List[str] = Field(default_factory=list, max_length=200)


# =============================================================================
# THREATFOX / URLhaus / OTX
# =============================================================================

class ThreatFoxResponse(BaseModel):
    """Schema para respuesta de ThreatFox"""
    found: bool = False
    malware: Optional[str] = Field(None, max_length=200)
    confidence_level: int = Field(0, ge=0, le=100)
    tags: List[str] = Field(default_factory=list, max_length=50)
    ioc_type: Optional[str] = Field(None, max_length=50)


class URLhausResponse(BaseModel):
    """Schema para respuesta de URLhaus"""
    found: bool = False
    threat: Optional[str] = Field(None, max_length=200)
    urls_count: int = Field(0, ge=0)
    tags: List[str] = Field(default_factory=list, max_length=50)


# =============================================================================
# PARSE HELPERS
# =============================================================================

def _safe_parse(model_class, raw: Dict[str, Any], api_name: str):
    """
    Parsea un dict con el schema Pydantic dado.
    Si falla la validación, logea la discrepancia y retorna None.
    """
    if not raw or not isinstance(raw, dict):
        return None
    if 'error' in raw:
        return None  # Error propio del cliente, no discrepancia de schema

    try:
        return model_class(**raw)
    except Exception as exc:
        logger.warning(
            f"API response schema mismatch for '{api_name}': {exc}. "
            f"Raw keys: {list(raw.keys())[:10]}"
        )
        return None


def parse_virustotal(raw: Dict[str, Any]) -> Optional[VirusTotalResponse]:
    return _safe_parse(VirusTotalResponse, raw, 'virustotal')


def parse_abuseipdb(raw: Dict[str, Any]) -> Optional[AbuseIPDBResponse]:
    return _safe_parse(AbuseIPDBResponse, raw, 'abuseipdb')


def parse_greynoise(raw: Dict[str, Any]) -> Optional[GreyNoiseResponse]:
    return _safe_parse(GreyNoiseResponse, raw, 'greynoise')


def parse_shodan(raw: Dict[str, Any]) -> Optional[ShodanResponse]:
    return _safe_parse(ShodanResponse, raw, 'shodan')


def parse_threatfox(raw: Dict[str, Any]) -> Optional[ThreatFoxResponse]:
    return _safe_parse(ThreatFoxResponse, raw, 'threatfox')


def parse_urlhaus(raw: Dict[str, Any]) -> Optional[URLhausResponse]:
    return _safe_parse(URLhausResponse, raw, 'urlhaus')
