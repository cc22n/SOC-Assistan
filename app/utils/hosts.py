"""
Validación de la cabecera Host contra ALLOWED_HOSTS (defensa contra Host Header Poisoning:
enlaces de reseteo/redirecciones/cachés construidos con un Host controlado por el atacante).

Sintaxis de cada entrada de ALLOWED_HOSTS (se ignora mayúsculas/minúsculas y el puerto):
  soc.example.com   coincidencia exacta
  .example.com      example.com y cualquier subdominio (a.example.com, a.b.example.com)
  127.0.0.1, [::1]  IPs literales
  *                 permite cualquier host (solo para entornos de prueba; desactiva la defensa)
"""
import re

_DNS_OR_IPV4 = re.compile(r'^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$')
_IPV6 = re.compile(r'^[0-9a-f:.]+$')


def split_host(host: str) -> str:
    """Devuelve el nombre sin puerto, en minúsculas. '[::1]:5000' -> '::1'; 'a.com:80' -> 'a.com'."""
    host = (host or '').strip().lower()
    if host.startswith('['):                       # IPv6 literal entre corchetes
        end = host.find(']')
        return host[1:end] if end != -1 else ''
    if host.count(':') == 1:                       # nombre:puerto
        return host.rsplit(':', 1)[0]
    return host


def is_well_formed(name: str) -> bool:
    """Descarta valores con caracteres que no pueden ser un hostname (espacios, '/', '@', '\\', ...)."""
    if not name or len(name) > 253:
        return False
    if ':' in name:
        return bool(_IPV6.match(name))
    return bool(_DNS_OR_IPV4.match(name))


def host_allowed(host: str, allowed_hosts) -> bool:
    """True si `host` (con o sin puerto) coincide con alguna entrada de `allowed_hosts`."""
    name = split_host(host)
    if not is_well_formed(name):
        return False
    for pattern in allowed_hosts or ():
        p = (pattern or '').strip().lower()
        if not p:
            continue
        if p == '*':
            return True
        if p.startswith('.'):
            if name == p[1:] or name.endswith(p):
                return True
        elif name == p.strip('[]'):
            return True
    return False
