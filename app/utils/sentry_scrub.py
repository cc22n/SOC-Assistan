"""
Sentry sin secretos (hallazgo 3 de prelaunch-report-3, REPRODUCIDO): el SDK guarda en cada breadcrumb la URL completa de las peticiones
salientes (`httplib`). La de Telegram lleva el token del bot DENTRO de la ruta (`/bot<TOKEN>/sendMessage`) y varias APIs de terceros
llevan su clave en la query (`?apiKey=...`). El redactado de `telegram_client` protegía logs, excepciones, auditoría y feed_runs, pero no
este camino: con `SENTRY_DSN` definido, el token salía a Sentry en el siguiente evento.

`before_breadcrumb` y `before_send` pasan TODO por `scrub()`: token de Telegram (`telegram_client.redact`), parámetros sensibles de query
(`apikey=`, `token=`, `key=`, `secret=`, `password=`...) y los valores de claves de diccionario sensibles (authorization, cookie...).
"""
import re
from typing import Any, Dict

from app.services.telegram_client import redact

REDACTED = '<REDACTED>'
_SENSITIVE_QS = re.compile(r'(?i)((?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|token|key|secret|password|passwd|signature|sig)=)'
                           r'[^&\s"\'<>]+')
_SENSITIVE_KEYS = {'authorization', 'proxy-authorization', 'cookie', 'set-cookie', 'x-api-key', 'x-apikey', 'api-key', 'apikey', 'api_key',
                   'key', 'token', 'secret', 'password', 'passwd', 'access_token', 'auth_token'}


def scrub(value: Any) -> Any:
    """Copia de `value` sin secretos (strings, dicts, listas y tuplas, recursivo)."""
    if isinstance(value, str):
        return _SENSITIVE_QS.sub(lambda m: m.group(1) + REDACTED, redact(value))
    if isinstance(value, dict):
        return {k: (REDACTED if isinstance(k, str) and k.lower() in _SENSITIVE_KEYS and v else scrub(v)) for k, v in value.items()}
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
                before_breadcrumb=before_breadcrumb, before_send=before_send)
