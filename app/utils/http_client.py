"""
Módulo HTTP centralizado con pooling de conexiones y keep-alive.
SOC Agent - Resiliencia y Rendimiento de Red.
"""
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Optional

_shared_session: Optional[requests.Session] = None


def get_http_session(
    pool_connections: int = 20,
    pool_maxsize: int = 50,
    max_retries: int = 2
) -> requests.Session:
    """
    Retorna una sesión singleton de requests configurada con connection pooling
    y reintentos para fallos transitorios de red.
    """
    global _shared_session
    if _shared_session is None:
        session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist=[502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        adapter = HTTPAdapter(
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
            max_retries=retry_strategy
        )
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        _shared_session = session

    return _shared_session


def _sanitized(exc: requests.RequestException) -> requests.RequestException:
    """
    La misma excepción con el mensaje SIN secretos (prelaunch-report-4 A2). El texto de una excepción de `requests` lleva la URL completa,
    con la clave de la API si viaja en la query; los clientes lo devuelven (`{'error': str(e)}`) y lo registran. Se conserva el TIPO
    (los `except requests.Timeout` siguen funcionando) y `.response`; se descarta `.request` (su `.url` lleva la clave).
    """
    from app.utils.secret_redaction import redact_secrets
    original = str(exc)
    limpio = redact_secrets(original)
    if limpio == original:
        return exc
    try:
        nueva = type(exc)(limpio)
    except Exception:
        nueva = requests.RequestException(limpio)
    resp = getattr(exc, 'response', None)
    if resp is not None:
        nueva.response = resp
    return nueva


def http_get(url: str, **kwargs) -> requests.Response:
    """Realiza una petición GET utilizando connection pooling persistente."""
    try:
        return get_http_session().get(url, **kwargs)
    except requests.RequestException as e:
        limpia = _sanitized(e)
        if limpia is e:
            raise
        raise limpia from None                  # `from None`: el traceback tampoco arrastra la excepción original con la clave


def http_post(url: str, **kwargs) -> requests.Response:
    """Realiza una petición POST utilizando connection pooling persistente."""
    try:
        return get_http_session().post(url, **kwargs)
    except requests.RequestException as e:
        limpia = _sanitized(e)
        if limpia is e:
            raise
        raise limpia from None
