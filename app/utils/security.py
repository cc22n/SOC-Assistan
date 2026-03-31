"""
SOC Agent - Utilidades de Seguridad
Fase 4 - T4A-01: Sanitización de prompts LLM contra prompt injection
"""
import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# =============================================================================
# PATRONES DE PROMPT INJECTION
# =============================================================================

# Patrones de instrucción directa al LLM
_INJECTION_PATTERNS = [
    # Override de instrucciones
    re.compile(r'\bignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)\b', re.I),
    re.compile(r'\b(disregard|forget|override|bypass)\s+(all\s+)?(instructions?|rules?|guidelines?|constraints?)\b', re.I),
    re.compile(r'\bdo\s+not\s+follow\s+(your\s+)?(previous|prior|original)\s+(instructions?|rules?)\b', re.I),

    # Role impersonation
    re.compile(r'\bact\s+as\s+(if\s+you\s+are\s+|a\s+|an\s+)?(dan|jailbreak|evil|unethical|unrestricted|uncensored)\b', re.I),
    re.compile(r'\byou\s+are\s+now\s+(in\s+)?(developer|jailbreak|dan|unrestricted|god)\s+mode\b', re.I),
    re.compile(r'\bpretend\s+(to\s+be|you\s+are)\s+(a\s+)?(different|evil|unrestricted|uncensored)\b', re.I),

    # Jailbreak clásicos
    re.compile(r'\bjailbreak\b', re.I),
    re.compile(r'\bdan\s+mode\b', re.I),
    re.compile(r'\bdo\s+anything\s+now\b', re.I),
    re.compile(r'\b(developer|debug)\s+mode\s+(enabled|on|activated)\b', re.I),

    # Exfiltración de sistema
    re.compile(r'\b(print|show|reveal|display|output|repeat)\s+(your\s+)?(system\s+prompt|instructions?|secret|api\s+key)\b', re.I),
    re.compile(r'\bwhat\s+(are|is)\s+your\s+(system\s+)?prompt\b', re.I),

    # Delimitadores de instrucción típicos en prompt injection
    re.compile(r'<\s*/?\s*(system|instruction|prompt|context)\s*>', re.I),
    re.compile(r'\[SYSTEM\]|\[INST\]|\[\/INST\]|\[ASSISTANT\]', re.I),
]

# Longitud máxima de campo de usuario antes de enviar al LLM
_MAX_USER_CONTEXT_LEN = 500
_MAX_CHAT_MESSAGE_LEN = 2000


def sanitize_llm_prompt(text: str, max_length: int = _MAX_USER_CONTEXT_LEN, field_name: str = "input") -> str:
    """
    Sanitiza texto de usuario antes de incluirlo en un prompt LLM.

    - Bloquea patrones de prompt injection conocidos
    - Escapa delimitadores de instrucción
    - Trunca al límite configurado

    Args:
        text: Texto del usuario a sanitizar
        max_length: Longitud máxima permitida (chars)
        field_name: Nombre del campo (para logs)

    Returns:
        Texto sanitizado y truncado. Retorna cadena vacía si se detecta
        intento de inyección severo.
    """
    if not text:
        return ""

    original = text

    # 1. Eliminar null bytes y caracteres de control no imprimibles
    text = text.replace('\x00', '').replace('\r', ' ')
    text = re.sub(r'[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)

    # 2. Detectar patrones de injection
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(text):
            logger.warning(
                f"Prompt injection attempt detected in field '{field_name}': "
                f"pattern='{pattern.pattern[:60]}' value='{text[:100]}'"
            )
            # Devolver vacío para no incluir el intento en el prompt
            return ""

    # 3. Escapar delimitadores de instrucción comunes para neutralizarlos
    text = text.replace('<<<', '&lt;&lt;&lt;')
    text = text.replace('>>>', '&gt;&gt;&gt;')
    text = re.sub(r'`{3,}', '```', text)  # limitar backticks consecutivos

    # 4. Truncar
    if len(text) > max_length:
        logger.debug(f"Field '{field_name}' truncated from {len(original)} to {max_length} chars")
        text = text[:max_length] + '...[truncated]'

    return text.strip()


def sanitize_chat_message(message: str) -> str:
    """
    Sanitiza un mensaje de chat antes de enviarlo al LLM.
    Usa límite más generoso que user_context.
    """
    return sanitize_llm_prompt(message, max_length=_MAX_CHAT_MESSAGE_LEN, field_name="chat_message")


def sanitize_user_context(context: str) -> str:
    """
    Sanitiza el campo 'context' del endpoint /analyze/enhanced.
    """
    return sanitize_llm_prompt(context, max_length=_MAX_USER_CONTEXT_LEN, field_name="user_context")
