"""
Async API Executor - Ejecucion paralela de APIs de Threat Intelligence
SOC Agent v2 - Sprint 1

Estrategia: ThreadPoolExecutor + asyncio.gather()
- Los clientes existentes usan requests (sync) y acceden a Flask current_app
- En vez de reescribir 1300+ lineas, ejecutamos cada cliente sync en su propio thread
- asyncio.gather() coordina la ejecucion paralela
- Resultado: 19 APIs en ~3s en vez de ~19s

Uso:
    from app.services.async_executor import execute_apis_parallel
    results = execute_apis_parallel(ioc, ioc_type, selected_apis, api_clients)
"""
import asyncio
import logging
import time
from typing import Dict, List, Any, Callable, Optional
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

# Pool de threads global - reutilizado entre requests
# max_workers=10 porque la mayoria de APIs tienen timeout de 15-30s
# y no queremos abrir 19 conexiones TCP simultaneas desde una sola IP
_executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix='api-worker')


async def _run_in_thread(func: Callable, *args) -> Any:
    """Ejecuta una funcion sync en un thread del pool"""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_executor, func, *args)


async def _execute_single_api(
    api_name: str,
    client: Any,
    ioc: str,
    ioc_type: str,
    timeout: float = 30.0
) -> tuple:
    """
    Ejecuta una sola API de forma async con timeout.

    Returns:
        (api_name, result_dict)
    """
    try:
        # Determinar que metodo llamar segun api_name y ioc_type
        method = _resolve_method(api_name, client, ioc, ioc_type)
        if method is None:
            return (api_name, None)  # API no soporta este ioc_type

        # Ejecutar con timeout
        result = await asyncio.wait_for(
            _run_in_thread(method),
            timeout=timeout
        )

        if result and 'error' not in result:
            logger.info(f"[ASYNC] {api_name} completed successfully")
        elif result and 'error' in result:
            logger.warning(f"[ASYNC] {api_name} returned error: {result['error'][:80]}")

        return (api_name, result)

    except asyncio.TimeoutError:
        logger.warning(f"[ASYNC] {api_name} timed out after {timeout}s")
        return (api_name, {'error': f'Timeout ({timeout}s)'})
    except Exception as e:
        logger.error(f"[ASYNC] {api_name} exception: {e}")
        return (api_name, {'error': str(e)})


def _resolve_method(api_name: str, client: Any, ioc: str, ioc_type: str) -> Optional[Callable]:
    """
    Determina que metodo del cliente llamar segun API y tipo de IOC.
    Retorna una funcion sin argumentos (closure) lista para ejecutar.
    """

    # Mapa de (api_name, ioc_type) -> lambda que llama al metodo correcto
    method_map = {
        # APIs Principales
        ('virustotal', 'ip'):       lambda: client.check_ip(ioc),
        ('virustotal', 'domain'):   lambda: client.check_domain(ioc),
        ('virustotal', 'hash'):     lambda: client.check_hash(ioc),
        ('virustotal', 'url'):      lambda: client.check_domain(ioc),

        ('abuseipdb', 'ip'):        lambda: client.check_ip(ioc),

        ('shodan', 'ip'):           lambda: client.check_ip(ioc),

        ('otx', 'ip'):              lambda: client.check_ip(ioc),
        ('otx', 'domain'):          lambda: client.check_domain(ioc),
        ('otx', 'hash'):            lambda: client.check_hash(ioc),

        ('greynoise', 'ip'):        lambda: client.check_ip(ioc),

        # APIs abuse.ch
        ('urlhaus', 'url'):         lambda: client.check_url(ioc),
        ('urlhaus', 'domain'):      lambda: client.check_host(ioc),
        ('urlhaus', 'ip'):          lambda: client.check_host(ioc),

        ('threatfox', 'ip'):        lambda: client.search_ioc(ioc),
        ('threatfox', 'domain'):    lambda: client.search_ioc(ioc),
        ('threatfox', 'hash'):      lambda: client.search_ioc(ioc),
        ('threatfox', 'url'):       lambda: client.search_ioc(ioc),

        ('malwarebazaar', 'hash'):  lambda: client.query_hash(ioc),

        # Otras APIs
        ('google_safebrowsing', 'url'):    lambda: client.check_url(ioc),
        ('google_safebrowsing', 'domain'): lambda: client.check_url(f'http://{ioc}'),

        ('securitytrails', 'domain'):      lambda: client.get_domain_details(ioc),

        ('hybrid_analysis', 'hash'):       lambda: client.search_hash(ioc),

        # APIs v3
        ('criminal_ip', 'ip'):      lambda: client.check_ip(ioc),
        ('criminal_ip', 'domain'):  lambda: client.check_domain(ioc),

        ('pulsedive', 'ip'):        lambda: client.get_indicator(ioc),
        ('pulsedive', 'domain'):    lambda: client.get_indicator(ioc),
        ('pulsedive', 'hash'):      lambda: client.get_indicator(ioc),
        ('pulsedive', 'url'):       lambda: client.get_indicator(ioc),

        ('urlscan', 'url'):         lambda: client.search(f'url:"{ioc}"'),
        ('urlscan', 'domain'):      lambda: client.search(f'domain:{ioc}'),

        ('shodan_internetdb', 'ip'): lambda: client.check_ip(ioc),

        ('ip_api', 'ip'):           lambda: client.get_geolocation(ioc),

        ('censys', 'ip'):           lambda: client.check_ip(ioc),

        ('ipinfo', 'ip'):           lambda: client.check_ip(ioc),
    }

    return method_map.get((api_name, ioc_type))


async def _execute_apis_async(
    ioc: str,
    ioc_type: str,
    selected_apis: List[str],
    api_clients: Dict[str, Any],
    timeout_per_api: float = 30.0
) -> Dict[str, Any]:
    """
    Core async: ejecuta todas las APIs seleccionadas en paralelo.

    Args:
        ioc: Valor del IOC
        ioc_type: Tipo (ip, domain, hash, url)
        selected_apis: Lista de APIs a consultar
        api_clients: Dict {api_name: client_instance}
        timeout_per_api: Timeout por API individual

    Returns:
        Dict {api_name: result_dict}
    """
    tasks = []

    for api_name in selected_apis:
        client = api_clients.get(api_name)
        if not client:
            continue

        task = _execute_single_api(
            api_name=api_name,
            client=client,
            ioc=ioc,
            ioc_type=ioc_type,
            timeout=timeout_per_api
        )
        tasks.append(task)

    if not tasks:
        return {}

    # Ejecutar todas en paralelo
    results_list = await asyncio.gather(*tasks, return_exceptions=True)

    # Procesar resultados
    results = {}
    for item in results_list:
        if isinstance(item, Exception):
            logger.error(f"[ASYNC] Unexpected exception: {item}")
            continue
        if isinstance(item, tuple) and len(item) == 2:
            api_name, result = item
            if result is not None:
                results[api_name] = result

    return results


def execute_apis_parallel(
    ioc: str,
    ioc_type: str,
    selected_apis: List[str],
    api_clients: Dict[str, Any],
    timeout_per_api: float = 30.0
) -> Dict[str, Any]:
    """
    Ejecuta APIs en paralelo (interfaz sincrona para Flask).

    Esta es la funcion que se llama desde el codigo sync de Flask.
    Internamente crea/reutiliza un event loop async.

    Args:
        ioc: Valor del IOC (ej: "8.8.8.8")
        ioc_type: Tipo (ip, domain, hash, url)
        selected_apis: Lista de APIs a consultar
        api_clients: Dict {api_name: client_instance}
        timeout_per_api: Timeout por API individual (default 30s)

    Returns:
        Dict {api_name: result_dict}

    Ejemplo:
        results = execute_apis_parallel(
            "8.8.8.8", "ip",
            ["virustotal", "abuseipdb", "shodan", "greynoise"],
            orchestrator.api_clients
        )
        # Todas se ejecutan al mismo tiempo, resultado en ~3s
    """
    start = time.time()
    n_apis = len(selected_apis)

    logger.info(f"[ASYNC] Starting parallel execution of {n_apis} APIs for {ioc} ({ioc_type})")

    try:
        # Intentar obtener loop existente
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Estamos dentro de un loop ya corriendo (raro en Flask, pero posible)
                # Usar nest_asyncio o crear nuevo loop en thread
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(
                        asyncio.run,
                        _execute_apis_async(ioc, ioc_type, selected_apis, api_clients, timeout_per_api)
                    )
                    results = future.result(timeout=timeout_per_api + 10)
            else:
                results = loop.run_until_complete(
                    _execute_apis_async(ioc, ioc_type, selected_apis, api_clients, timeout_per_api)
                )
        except RuntimeError:
            # No hay loop - crear uno nuevo
            results = asyncio.run(
                _execute_apis_async(ioc, ioc_type, selected_apis, api_clients, timeout_per_api)
            )

    except Exception as e:
        logger.error(f"[ASYNC] Parallel execution failed: {e}, falling back to sequential")
        results = _fallback_sequential(ioc, ioc_type, selected_apis, api_clients)

    elapsed = time.time() - start
    successful = sum(1 for v in results.values() if isinstance(v, dict) and 'error' not in v)

    logger.info(
        f"[ASYNC] Completed {successful}/{n_apis} APIs in {elapsed:.1f}s "
        f"(speedup vs sequential: ~{n_apis * 2:.0f}s -> {elapsed:.1f}s)"
    )

    return results


def _fallback_sequential(
    ioc: str,
    ioc_type: str,
    selected_apis: List[str],
    api_clients: Dict[str, Any]
) -> Dict[str, Any]:
    """Fallback sincrono si async falla"""
    logger.warning("[ASYNC] Using sequential fallback")
    results = {}

    for api_name in selected_apis:
        client = api_clients.get(api_name)
        if not client:
            continue

        method = _resolve_method(api_name, client, ioc, ioc_type)
        if method is None:
            continue

        try:
            result = method()
            if result:
                results[api_name] = result
        except Exception as e:
            logger.error(f"[SEQ] {api_name} error: {e}")
            results[api_name] = {'error': str(e)}

    return results
