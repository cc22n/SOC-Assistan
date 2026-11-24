"""
Sentry sin secretos (prelaunch-report-3 hallazgo 3 y prelaunch-report-4 A3, ambos REPRODUCIDOS).

El SDK guarda en cada breadcrumb y en cada span la URL completa de las peticiones salientes: la de Telegram lleva el token en la ruta y
varias APIs llevan su clave en la query (`?key=`, `?token=`, `?apiKey=`). Además adjunta las VARIABLES LOCALES de cada frame de una
excepción (`auth_key`, `vt_api_key`...), y las cabeceras de abuse.ch (`Auth-Key`) y OTX (`X-OTX-API-KEY`) no coincidían por igualdad
exacta con una lista corta de nombres. La primera versión de este filtro cubría breadcrumbs y eventos, pero no las TRANSACCIONES
(traces_sample_rate=5 % mandaba las claves de ~1 de cada 20 análisis).

Ahora:
  * `before_breadcrumb`, `before_send` y `before_send_transaction` pasan TODO por `scrub()`;
  * los valores se redactan con `secret_redaction` (el valor de cada secreto configurado, el token de Telegram, la query, `Bearer`...);
  * los NOMBRES de clave de dict se juzgan por patrón (`*api-key*`, `*token*`, `*secret*`, `*passw*`, `auth-key`...), no por igualdad;
  * `include_local_variables=False`: no se envían las variables locales de los frames (es donde viven las claves).
"""
import re
from typing import Any, Dict

from app.utils.secret_redaction import REDACTED, redact_secrets

_SENSITIVE_KEY = re.compile(r'(?i)(api[-_ ]?key|auth[-_ ]?key|access[-_ ]?key|apikey|secret|token|passw|authorization|cookie|'
                            r'credential|bearer|signature|private)')
_SENSITIVE_EXACT = {'key', 'sig', 'pwd', 'dsn'}


def _sensitive_name(k: Any) -> bool:
    return isinstance(k, str) and (k.lower() in _SENSITIVE_EXACT or bool(_SENSITIVE_KEY.search(k)))


def scrub(value: Any) -> Any:
    """Copia de `value` sin secretos (strings, dicts, listas y tuplas, recursivo)."""
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, dict):
        return {k: (REDACTED if _sensitive_name(k) and v else scrub(v)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(scrub(v) for v in value)
    return value


def before_breadcrumb(crumb: Dict[str, Any], hint: Any = None) -> Dict[str, Any]:
    return scrub(crumb)


def before_send(event: Dict[str, Any], hint: Any = None) -> Dict[str, Any]:
    return scrub(event)


def sentry_init_kwargs(dsn: str, *integrations) -> Dict[str, Any]:
    """Argumentos de `sentry_sdk.init` con los filtros siempre puestos (un solo sitio, probado)."""
    return dict(dsn=dsn, integrations=list(integrations), traces_sample_rate=0.05, send_default_pii=False,
                include_local_variables=False, max_breadcrumbs=50,
                before_breadcrumb=before_breadcrumb, before_send=before_send, before_send_transaction=before_send)
