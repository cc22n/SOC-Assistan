"""
SOC Agent - Pydantic Schemas
Sprint 3 - Request/Response validation

Schemas tipados para todos los endpoints de la API v2.
Reemplazan la validación manual con regex por modelos Pydantic
que dan mensajes de error claros y auto-documentan la API.

Uso:
    from app.schemas.api import AnalyzeRequest
    data = AnalyzeRequest(**request.get_json())  # Valida automáticamente
"""
from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# =============================================================================
# ENUMS
# =============================================================================

class IOCType(str, Enum):
    IP = 'ip'
    DOMAIN = 'domain'
    HASH = 'hash'
    URL = 'url'


class RiskLevel(str, Enum):
    CRITICO = 'CRÍTICO'
    CRITICO_ASCII = 'CRITICO'
    ALTO = 'ALTO'
    MEDIO = 'MEDIO'
    BAJO = 'BAJO'
    LIMPIO = 'LIMPIO'


class IncidentSeverity(str, Enum):
    CRITICAL = 'critical'
    HIGH = 'high'
    MEDIUM = 'medium'
    LOW = 'low'
    INFO = 'info'


class IncidentStatus(str, Enum):
    OPEN = 'open'
    INVESTIGATING = 'investigating'
    RESOLVED = 'resolved'
    CLOSED = 'closed'


# =============================================================================
# IOC VALIDATORS (reusables)
# =============================================================================

# Patterns
IPV4_PATTERN = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)
DOMAIN_PATTERN = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)
MD5_PATTERN = re.compile(r'^[a-fA-F0-9]{32}$')
SHA1_PATTERN = re.compile(r'^[a-fA-F0-9]{40}$')
SHA256_PATTERN = re.compile(r'^[a-fA-F0-9]{64}$')
URL_PATTERN = re.compile(r'^https?://.+')


def validate_ioc_value(value: str, ioc_type: Optional[str] = None) -> str:
    """Valida y limpia un valor de IOC"""
    value = value.strip()
    if not value:
        raise ValueError('IOC value cannot be empty')
    if len(value) > 2048:
        raise ValueError('IOC value too long (max 2048 chars)')

    # Detectar caracteres peligrosos
    dangerous = set('<>{}();\'"\\`$|&')
    if ioc_type != 'url' and any(c in value for c in dangerous):
        raise ValueError('IOC contains dangerous characters')

    # Validar por tipo si se proporciona
    if ioc_type == 'ip':
        if not IPV4_PATTERN.match(value):
            raise ValueError(f'Invalid IPv4 address: {value}')
    elif ioc_type == 'domain':
        if not DOMAIN_PATTERN.match(value):
            raise ValueError(f'Invalid domain: {value}')
    elif ioc_type == 'hash':
        if not (MD5_PATTERN.match(value) or SHA1_PATTERN.match(value) or SHA256_PATTERN.match(value)):
            raise ValueError(f'Invalid hash (expected MD5, SHA1, or SHA256): {value}')
    elif ioc_type == 'url':
        if not URL_PATTERN.match(value):
            raise ValueError(f'Invalid URL (must start with http:// or https://): {value}')

    return value


# =============================================================================
# ANALYSIS SCHEMAS
# =============================================================================

class AnalyzeRequest(BaseModel):
    """POST /api/v2/analyze/enhanced"""
    ioc: str = Field(..., min_length=1, max_length=2048, description='IOC value to analyze')
    type: Optional[IOCType] = Field(None, description='IOC type (auto-detected if omitted)')
    context: str = Field('', max_length=5000, description='User context for LLM analysis')
    use_llm_planning: bool = Field(True, description='Enable LLM-guided API selection')
    session_id: Optional[int] = Field(None, ge=1, description='Investigation session ID')
    force_refresh: bool = Field(False, description='Bypass cache and force fresh analysis')

    @field_validator('ioc')
    @classmethod
    def clean_ioc(cls, v):
        return v.strip()

    @model_validator(mode='after')
    def validate_ioc_by_type(self):
        if self.type:
            validate_ioc_value(self.ioc, self.type.value)
        return self


class AnalyzeResponse(BaseModel):
    """Response for /api/v2/analyze/enhanced"""
    success: bool
    analysis_id: int
    ioc: str
    type: str
    confidence_score: int = Field(ge=0, le=100)
    risk_level: str
    llm_analysis: Optional[Dict[str, Any]] = None
    sources_used: List[str] = []
    api_results: Dict[str, Any] = {}
    mitre_techniques: List[Any] = []
    processing_time: float = Field(ge=0)
    session_id: Optional[int] = None
    timestamp: Optional[str] = None
    cached: bool = False
    cache_age_minutes: Optional[int] = None


# =============================================================================
# CHAT SCHEMAS
# =============================================================================

class ChatMessageRequest(BaseModel):
    """POST /api/v2/chat/message"""
    message: str = Field(..., min_length=1, max_length=10000, description='Chat message')
    session_id: Optional[int] = Field(None, ge=1)
    llm_provider: Optional[str] = Field(None, max_length=30)
    history: List[Dict[str, str]] = Field(default_factory=list, max_length=50)

    @field_validator('message')
    @classmethod
    def clean_message(cls, v):
        v = v.strip()
        if not v:
            raise ValueError('Message cannot be empty')
        return v

    @field_validator('llm_provider')
    @classmethod
    def valid_provider(cls, v):
        if v and v not in ('xai', 'openai', 'groq', 'gemini'):
            raise ValueError(f'Invalid LLM provider: {v}. Must be xai, openai, groq, or gemini')
        return v


class ChatMessageResponse(BaseModel):
    """Response for /api/v2/chat/message"""
    success: bool
    response: str
    session_id: Optional[int] = None
    iocs_detected: List[str] = []
    timestamp: Optional[str] = None


# =============================================================================
# INCIDENT SCHEMAS
# =============================================================================

class IncidentCreateRequest(BaseModel):
    """POST /api/incidents"""
    title: str = Field(..., min_length=3, max_length=200)
    description: Optional[str] = Field(None, max_length=5000)
    severity: IncidentSeverity = Field(IncidentSeverity.MEDIUM)
    analysis_id: Optional[int] = Field(None, ge=1)
    session_id: Optional[int] = Field(None, ge=1)
    ioc_ids: List[int] = Field(default_factory=list)


class IncidentUpdateRequest(BaseModel):
    """PUT /api/incidents/<id>"""
    title: Optional[str] = Field(None, min_length=3, max_length=200)
    description: Optional[str] = Field(None, max_length=5000)
    severity: Optional[IncidentSeverity] = None
    status: Optional[IncidentStatus] = None
    notes: Optional[str] = Field(None, max_length=10000)


class IncidentResponse(BaseModel):
    """Response for incident endpoints"""
    id: int
    ticket_id: str
    title: str
    description: Optional[str] = None
    severity: Optional[str] = None
    status: str
    created_at: str
    updated_at: Optional[str] = None
    resolved_at: Optional[str] = None
    notes: Optional[str] = None


# =============================================================================
# SESSION SCHEMAS
# =============================================================================

class SessionCreateRequest(BaseModel):
    """POST /api/v2/sessions"""
    title: Optional[str] = Field(None, max_length=200)
    description: Optional[str] = Field(None, max_length=2000)


class SessionResponse(BaseModel):
    """Response for session endpoints"""
    id: int
    uuid: str
    title: Optional[str] = None
    status: str
    created_at: str
    total_iocs: int = 0
    total_messages: int = 0
    highest_risk_level: Optional[str] = None


# =============================================================================
# REPORT SCHEMAS
# =============================================================================

class ReportGenerateRequest(BaseModel):
    """POST /api/reports/generate"""
    analysis_id: int = Field(..., ge=1)
    format: str = Field('pdf', pattern=r'^(pdf|docx)$')
    include_api_details: bool = Field(True)
    include_mitre: bool = Field(True)


# =============================================================================
# GENERIC ERROR RESPONSE
# =============================================================================

class ErrorResponse(BaseModel):
    """Standard error response"""
    error: str
    details: Optional[Dict[str, Any]] = None
    status_code: int = 400