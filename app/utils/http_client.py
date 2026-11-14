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


def http_get(url: str, **kwargs) -> requests.Response:
    """Realiza una petición GET utilizando connection pooling persistente."""
    return get_http_session().get(url, **kwargs)


def http_post(url: str, **kwargs) -> requests.Response:
    """Realiza una petición POST utilizando connection pooling persistente."""
    return get_http_session().post(url, **kwargs)
