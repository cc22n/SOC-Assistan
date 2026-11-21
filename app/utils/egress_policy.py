"""
Política de salida (WP4 de PLAN-FUSION, "AgentGate" adaptado): qué IOCs pueden salir de SOC Agent hacia APIs de terceros.

Origen: ThreatChain `agentgate/` (PDP determinista con ALLOW/DENY/MASK/REQUIRE_APPROVAL). Aquí solo ALLOW, DENY y MASK, sin
estado ni servicio (función pura). REQUIRE_APPROVAL queda reservado en el tipo y NO se implementa: SOC Agent solo hace lecturas
y no hay segundo humano ni canal al que pedir aprobación (ver PLAN-WP4-AGENTGATE.md).

Por qué existe (verificado por ejecución el 2026-11-20): la regla "una IP privada no llega a ninguna API externa" solo se aplicaba
en `validate_ioc` (ruta de análisis profundo). La ruta principal y el chat dejaban salir IPs privadas, URLs a 169.254.169.254,
`localhost` y dominios `.lan`/`.local` a hasta 10 terceros; en el chat el IOC lo decide el MODELO, sin validación alguna.

Una sola definición de "interno" para todos los puntos de enganche: `evaluate`/`enforce` (IOC) y `mask_text` (texto libre).

Límites (documentados, no ocultos):
  * Un dominio interno con nombre PÚBLICO (`intranet.empresa.com`) no se detecta solo: se declara en EGRESS_INTERNAL_DOMAINS.
  * `mask_text` usa expresiones regulares: reduce la fuga, no la garantiza (un host interno de una sola etiqueta no se detecta en texto libre).
  * No protege datos sensibles que no sean IOCs (credenciales pegadas en un mensaje).
"""
import ipaddress
import re
import socket
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Sequence, Tuple
from urllib.parse import urlsplit

from app.utils.validators import (
    is_private_ip, is_valid_cve, is_valid_domain, is_valid_hash, is_valid_ip, is_valid_url,
)


class Decision(str, Enum):
    ALLOW = 'ALLOW'
    DENY = 'DENY'
    MASK = 'MASK'
    REQUIRE_APPROVAL = 'REQUIRE_APPROVAL'      # RESERVADO: no se emite en esta versión


@dataclass(frozen=True)
class Verdict:
    decision: Decision
    rule: str = ''
    reason: str = ''

    @property
    def allowed(self) -> bool:
        return self.decision == Decision.ALLOW


class EgressDenied(ValueError):
    """El IOC no puede salir hacia APIs externas. Lleva el veredicto para auditarlo y explicárselo al analista."""

    def __init__(self, verdict: Verdict):
        self.verdict = verdict
        super().__init__(verdict.reason)


# Sufijos que no se resuelven en Internet público (RFC 6762 .local, RFC 6761 .localhost, RFC 8375 .home.arpa, ICANN .internal)
# y los que usan las redes corporativas sin estar delegados (.lan, .corp, .home, .intranet, .private, .localdomain).
INTERNAL_SUFFIXES: Tuple[str, ...] = (
    'local', 'localhost', 'internal', 'lan', 'corp', 'home', 'intranet', 'private', 'localdomain', 'home.arpa',
)
PLACEHOLDER_IP = '[IP_INTERNA]'
PLACEHOLDER_HOST = '[HOST_INTERNO]'

_NUMERIC_HOST = re.compile(r'^(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}$', re.IGNORECASE)
KNOWN_TYPES = ('ip', 'domain', 'url', 'hash', 'cve')


def configured_domains() -> Tuple[str, ...]:
    """Dominios propios declarados (EGRESS_INTERNAL_DOMAINS, por límite de etiqueta, nunca por subcadena)."""
    try:
        from flask import current_app
        return tuple(current_app.config.get('EGRESS_INTERNAL_DOMAINS') or ())
    except RuntimeError:                       # fuera de contexto de aplicación
        return ()


def _numeric_to_ip(host: str) -> Optional[str]:
    """Formas que los resolutores aceptan como IPv4 pero que el ojo no ve: 127.1, 2130706433, 0x7f.0.0.1, 017700000001."""
    if not _NUMERIC_HOST.match(host):
        return None
    try:
        return socket.inet_ntoa(socket.inet_aton(host))
    except OSError:
        return None


def host_internal_rule(host: Optional[str], extra_domains: Sequence[str] = ()) -> Optional[Tuple[str, str]]:
    """(regla, motivo) si el host es interno; None si es público. Un host vacío o inválido se trata como interno (falla cerrado)."""
    host = (host or '').strip().lower().rstrip('.')
    if '%' in host:                            # zona IPv6: fe80::1%eth0
        host = host.split('%', 1)[0]
    if not host:
        return 'host_invalido', 'no se pudo determinar el host del IOC'
    ip = _numeric_to_ip(host)
    if ip is None:
        try:
            ip = str(ipaddress.ip_address(host))
        except ValueError:
            ip = None
    if ip is not None:
        if is_private_ip(ip):
            return 'ip_interna', f'{ip} es una dirección privada, de loopback, link-local o reservada'
        return None
    if host == 'localhost':
        return 'host_interno', 'localhost es un nombre interno'
    if '.' not in host:
        return 'host_interno', f"'{host}' es un nombre de una sola etiqueta (solo resuelve dentro de una red local)"
    for suffix in INTERNAL_SUFFIXES:
        if host == suffix or host.endswith('.' + suffix):
            return 'host_interno', f"el sufijo .{suffix} no existe en Internet público"
    for dom in tuple(extra_domains) + configured_domains():
        dom = dom.strip().lower().strip('.')
        if dom and (host == dom or host.endswith('.' + dom)):
            return 'dominio_propio', f'{dom} está declarado como dominio interno de la organización'
    return None


def _format_ok(value: str, ioc_type: str) -> bool:
    if ioc_type == 'ip':
        if is_valid_ip(value):
            return True
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    if ioc_type == 'domain':
        return is_valid_domain(value)
    if ioc_type == 'url':
        return is_valid_url(value)
    if ioc_type == 'hash':
        return is_valid_hash(value)
    if ioc_type == 'cve':
        return is_valid_cve(value)
    return True


def evaluate(value: Optional[str], ioc_type: Optional[str], extra_domains: Sequence[str] = ()) -> Verdict:
    """
    Veredicto para un IOC que va a salir hacia APIs externas.
      DENY  si el formato no es el de su tipo (en el chat el IOC lo decide el modelo: no se confía), o si es interno.
      ALLOW en cualquier otro caso. Los tipos desconocidos no se bloquean: no tienen estrategia, no se consulta ninguna API.
    """
    if ioc_type not in KNOWN_TYPES:
        return Verdict(Decision.ALLOW)
    value = (value or '').strip()
    if not value or not _format_ok(value, ioc_type):
        return Verdict(Decision.DENY, 'formato_invalido', f'el valor no tiene el formato de un IOC de tipo {ioc_type}')
    if ioc_type in ('hash', 'cve'):
        return Verdict(Decision.ALLOW)
    if ioc_type == 'url':
        try:
            host = urlsplit(value).hostname
        except ValueError:
            host = None
    else:
        host = value
    hit = host_internal_rule(host, extra_domains)
    if hit:
        return Verdict(Decision.DENY, hit[0], hit[1])
    return Verdict(Decision.ALLOW)


def explain(verdict: Verdict) -> str:
    """Mensaje para el analista: qué pasó y por qué, sin tecnicismos."""
    if verdict.rule == 'formato_invalido':
        return f'IOC rechazado: {verdict.reason}.'
    return (f'IOC interno: no se envía a servicios de terceros ({verdict.reason}). '
            'Los análisis consultan APIs externas y enviarían tu infraestructura interna a empresas ajenas.')


def audit_denied(verdict: Verdict, value: Optional[str], ioc_type: Optional[str], origin: str,
                 user_id: Optional[int] = None) -> None:
    """
    Deja constancia de un DENY: `AuditEvent('egress_denied')` con la regla, el tipo y el IOC truncado. NO se audita ALLOW (20 por
    análisis inundarían la tabla). Hace commit: es una ruta terminal (el análisis no continúa). Nunca lanza.
    """
    try:
        from app.models.audit import AuditEvent
        AuditEvent.log('egress_denied', resource_type='ioc', success=False, user_id=user_id,
                       details={'rule': verdict.rule, 'reason': verdict.reason, 'ioc_type': ioc_type,
                                'ioc': (value or '')[:200], 'origin': origin}, _commit=True)
    except Exception:                                       # la auditoría no debe convertir un rechazo en un 500
        import logging
        logging.getLogger(__name__).exception('no se pudo auditar egress_denied')


def enforce(value: Optional[str], ioc_type: Optional[str]) -> Verdict:
    """Como `evaluate`, pero lanza `EgressDenied` si el veredicto es DENY."""
    verdict = evaluate(value, ioc_type)
    if verdict.decision == Decision.DENY:
        raise EgressDenied(verdict)
    return verdict


# --------------------------------------------------------------------------- texto libre (MASK)

_IPV4_IN_TEXT = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d])')


def _host_pattern(extra: Sequence[str]) -> 're.Pattern':
    sufijos = [re.escape(s) for s in INTERNAL_SUFFIXES]
    sufijos += [re.escape(d.strip().lower().strip('.')) for d in tuple(extra) + configured_domains() if d.strip().strip('.')]
    alternativa = '|'.join(sorted(sufijos, key=len, reverse=True))
    # una o más etiquetas seguidas de un sufijo interno (o 'localhost' solo). El sufijo solo cuenta si TERMINA el nombre: no debe
    # pegarse a letras/guiones ni continuar con otra etiqueta ('a.local.com' es público: el lookahead lo impide, mientras que un
    # punto final de frase, 'cae host.local.', sí se permite).
    fin = r'(?![\w-]|\.[\w])'
    return re.compile(rf'(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:{alternativa}){fin}|(?<![\w.-])localhost{fin}',
                      re.IGNORECASE)


def mask_text(text: Optional[str], extra_domains: Sequence[str] = ()) -> Tuple[str, int]:
    """
    Sustituye IPs privadas y nombres de host internos del texto libre (contexto del analista, mensaje de chat) por marcadores,
    antes de que lleguen a un LLM o a una búsqueda web. Devuelve (texto, nº de sustituciones). No toca IPs públicas, CVE ni hashes.
    """
    if not text:
        return text or '', 0
    count = 0

    def ip(m: 're.Match') -> str:
        nonlocal count
        candidato = m.group(0)
        if is_valid_ip(candidato) and is_private_ip(candidato):
            count += 1
            return PLACEHOLDER_IP
        return candidato

    def host(m: 're.Match') -> str:
        nonlocal count
        count += 1
        return PLACEHOLDER_HOST

    text = _IPV4_IN_TEXT.sub(ip, text)
    text = _host_pattern(extra_domains).sub(host, text)
    return text, count
