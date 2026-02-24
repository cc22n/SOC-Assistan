"""
Validadores y detectores de IOCs
"""
import re
from typing import Optional


def is_valid_ip(ip: str) -> bool:
    """Valida formato de dirección IP"""
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        return all(0 <= int(part) <= 255 for part in parts)
    except (ValueError, AttributeError):
        return False


def is_private_ip(ip: str) -> bool:
    """Verifica si es IP privada (RFC 1918)"""
    try:
        parts = [int(part) for part in ip.split('.')]
        # RFC 1918 ranges
        return (
                parts[0] == 10 or
                (parts[0] == 172 and 16 <= parts[1] <= 31) or
                (parts[0] == 192 and parts[1] == 168) or
                parts[0] == 127  # Localhost
        )
    except (ValueError, IndexError):
        return False


def is_valid_hash(hash_value: str) -> bool:
    """Valida si es un hash válido (MD5, SHA1, SHA256)"""
    hash_len = len(hash_value)

    # MD5: 32, SHA1: 40, SHA256: 64
    if hash_len not in [32, 40, 64]:
        return False

    # Solo caracteres hexadecimales
    return bool(re.match(r'^[a-fA-F0-9]+$', hash_value))


def is_valid_domain(domain: str) -> bool:
    """Valida formato de dominio"""
    if len(domain) > 253 or len(domain) < 4:
        return False

    # Patrón básico de dominio
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def is_valid_url(url: str) -> bool:
    """Valida formato de URL"""
    pattern = r'^https?://[^\s<>"{}|\\^`\[\]]+$'
    return bool(re.match(pattern, url))


def detect_ioc_type(ioc: str) -> Optional[str]:
    """
    Detecta automáticamente el tipo de IOC

    Args:
        ioc: Valor del IOC

    Returns:
        'ip', 'hash', 'domain', 'url' o None
    """
    ioc = ioc.strip()

    # URL (debe ir primero)
    if is_valid_url(ioc):
        return 'url'

    # IP
    if is_valid_ip(ioc):
        return 'ip'

    # Hash
    if is_valid_hash(ioc):
        return 'hash'

    # Domain
    if is_valid_domain(ioc):
        return 'domain'

    return None


def validate_ioc(ioc: str, ioc_type: str) -> tuple:
    """
    Valida un IOC según su tipo

    Args:
        ioc: Valor del IOC
        ioc_type: Tipo esperado ('ip', 'hash', 'domain', 'url')

    Returns:
        Tuple (is_valid, error_message)
    """
    if not ioc or not ioc.strip():
        return False, "IOC value cannot be empty"

    ioc = ioc.strip()

    if ioc_type not in ('ip', 'hash', 'domain', 'url'):
        return False, f"Invalid IOC type: {ioc_type}"

    validators = {
        'ip': (is_valid_ip, "Invalid IP address format"),
        'hash': (is_valid_hash, "Invalid hash format (expected MD5/SHA1/SHA256)"),
        'domain': (is_valid_domain, "Invalid domain format"),
        'url': (is_valid_url, "Invalid URL format"),
    }

    validator_fn, error_msg = validators[ioc_type]
    if not validator_fn(ioc):
        return False, error_msg

    # Rechazar IPs privadas
    if ioc_type == 'ip' and is_private_ip(ioc):
        return False, "Private/reserved IP addresses cannot be analyzed"

    return True, ""


def sanitize_chat_input(message: str, max_length: int = 2000) -> tuple:
    """
    Sanitiza input del chat.

    Args:
        message: Mensaje del usuario
        max_length: Longitud máxima permitida

    Returns:
        Tuple (sanitized_message, was_truncated)
    """
    if not message or not message.strip():
        return "", True

    original_len = len(message)
    # Truncar a longitud máxima
    message = message[:max_length]
    # Eliminar null bytes
    message = message.replace('\x00', '')
    # Normalizar whitespace excesivo
    message = re.sub(r'\n{4,}', '\n\n\n', message)

    return message.strip(), len(message.strip()) < original_len


def extract_iocs_from_text(text: str) -> list:
    """
    Extrae todos los IOCs de un texto

    Args:
        text: Texto a analizar

    Returns:
        Lista de tuplas (ioc_value, ioc_type)
    """
    iocs = []

    # Patrones de búsqueda
    patterns = {
        'url': r'https?://[^\s<>"{}|\\^`\[\]]+',
        'ip': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        'hash': r'\b[a-fA-F0-9]{32,64}\b',
        'domain': r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,})\b'
    }

    for ioc_type, pattern in patterns.items():
        matches = re.findall(pattern, text)

        for match in matches:
            # Para domains, match puede ser tupla del regex
            if isinstance(match, tuple):
                match = match[0] if match else ''

            if not match:
                continue

            # Validaciones adicionales
            if ioc_type == 'hash':
                if len(match) in [32, 40, 64]:
                    iocs.append((match, 'hash'))

            elif ioc_type == 'ip':
                if is_valid_ip(match) and not is_private_ip(match):
                    iocs.append((match, 'ip'))

            elif ioc_type == 'domain':
                if is_valid_domain(match):
                    iocs.append((match, 'domain'))

            elif ioc_type == 'url':
                iocs.append((match, 'url'))

    # Eliminar duplicados manteniendo orden
    seen = set()
    unique_iocs = []
    for ioc, ioc_type in iocs:
        if ioc not in seen:
            seen.add(ioc)
            unique_iocs.append((ioc, ioc_type))

    return unique_iocs