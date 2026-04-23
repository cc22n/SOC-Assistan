"""
SOC Agent - Circuit Breaker para APIs Externas
Fase 4 - T4B-01

Implementa el patrón Circuit Breaker para proteger el sistema cuando
una API externa falla repetidamente.

Estados:
  CLOSED   → Operación normal. Las llamadas pasan.
  OPEN     → API marcada como caída. Las llamadas son rechazadas inmediatamente.
  HALF_OPEN → Período de prueba. Se permite una llamada para comprobar si la API se recuperó.

Uso:
    from app.utils.circuit_breaker import get_circuit_breaker

    cb = get_circuit_breaker('virustotal')
    if cb.allow_request():
        try:
            result = call_virustotal(...)
            cb.record_success()
        except Exception:
            cb.record_failure()
            result = {'error': 'circuit open'}
    else:
        result = {'error': 'circuit open', 'circuit_state': 'OPEN'}
"""
import logging
import threading
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class CircuitState(str, Enum):
    CLOSED = 'CLOSED'
    OPEN = 'OPEN'
    HALF_OPEN = 'HALF_OPEN'


class APICircuitBreaker:
    """
    Circuit breaker thread-safe para una API externa.

    Args:
        api_name: Nombre de la API (para logs y dashboard)
        fail_threshold: Número de fallos consecutivos para abrir el circuito
        timeout: Segundos en estado OPEN antes de pasar a HALF_OPEN
        success_threshold: Éxitos consecutivos en HALF_OPEN para volver a CLOSED
    """

    def __init__(
        self,
        api_name: str,
        fail_threshold: int = 3,
        timeout: int = 60,
        success_threshold: int = 1,
    ) -> None:
        self.api_name = api_name
        self.fail_threshold = fail_threshold
        self.timeout = timeout
        self.success_threshold = success_threshold

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[datetime] = None
        self._opened_at: Optional[datetime] = None
        self._lock = threading.Lock()
        # True while exactly one probe request is in-flight in HALF_OPEN state.
        # Prevents multiple concurrent threads from probing simultaneously, which
        # could all fail before any succeeds and keep the circuit perpetually open.
        self._probe_in_flight: bool = False

    @property
    def state(self) -> CircuitState:
        with self._lock:
            return self._get_state()

    def _get_state(self) -> CircuitState:
        """Evalua si debemos transitar de OPEN -> HALF_OPEN (llamar sin lock)."""
        if self._state == CircuitState.OPEN:
            if self._opened_at and datetime.utcnow() >= self._opened_at + timedelta(seconds=self.timeout):
                self._state = CircuitState.HALF_OPEN
                self._success_count = 0
                self._probe_in_flight = False  # fresh probe window
                logger.info(f"[Circuit:{self.api_name}] OPEN -> HALF_OPEN after {self.timeout}s")
        return self._state

    def allow_request(self) -> bool:
        """Retorna True si la llamada debe ejecutarse."""
        with self._lock:
            state = self._get_state()
            if state == CircuitState.CLOSED:
                return True
            if state == CircuitState.HALF_OPEN:
                # Allow only ONE probe at a time. If a probe is already in-flight,
                # block other threads until we know whether the API recovered.
                if self._probe_in_flight:
                    return False
                self._probe_in_flight = True
                return True
            # OPEN
            return False

    def record_success(self) -> None:
        """Registra una llamada exitosa."""
        with self._lock:
            state = self._get_state()
            if state == CircuitState.HALF_OPEN:
                self._probe_in_flight = False
                self._success_count += 1
                if self._success_count >= self.success_threshold:
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
                    self._success_count = 0
                    self._opened_at = None
                    logger.info(f"[Circuit:{self.api_name}] HALF_OPEN -> CLOSED (recovered)")
            elif state == CircuitState.CLOSED:
                # Reset contador de fallos en exito
                self._failure_count = 0

    def record_failure(self) -> None:
        """Registra una llamada fallida."""
        with self._lock:
            state = self._get_state()
            self._failure_count += 1
            self._last_failure_time = datetime.utcnow()

            if state == CircuitState.HALF_OPEN:
                # Fallo en prueba -> volver a OPEN
                self._probe_in_flight = False
                self._state = CircuitState.OPEN
                self._opened_at = datetime.utcnow()
                self._success_count = 0
                logger.warning(f"[Circuit:{self.api_name}] HALF_OPEN -> OPEN (probe failed)")

            elif state == CircuitState.CLOSED and self._failure_count >= self.fail_threshold:
                self._state = CircuitState.OPEN
                self._opened_at = datetime.utcnow()
                logger.warning(
                    f"[Circuit:{self.api_name}] CLOSED → OPEN "
                    f"({self._failure_count} failures, timeout={self.timeout}s)"
                )

    def get_status(self) -> Dict:
        """Retorna el estado actual para el dashboard de salud."""
        with self._lock:
            state = self._get_state()
            time_until_retry = None
            if state == CircuitState.OPEN and self._opened_at:
                remaining = (self._opened_at + timedelta(seconds=self.timeout) - datetime.utcnow()).total_seconds()
                time_until_retry = max(0, round(remaining))
            return {
                'api': self.api_name,
                'state': state.value,
                'failure_count': self._failure_count,
                'last_failure': self._last_failure_time.isoformat() if self._last_failure_time else None,
                'time_until_retry_s': time_until_retry,
            }

    def reset(self) -> None:
        """Resetea el circuit breaker a CLOSED (para tests o mantenimiento)."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._success_count = 0
            self._opened_at = None
            self._last_failure_time = None
            self._probe_in_flight = False
        logger.info(f"[Circuit:{self.api_name}] manually reset to CLOSED")


# =============================================================================
# REGISTRO GLOBAL (un CB por API, shared entre requests)
# =============================================================================

_circuit_breakers: Dict[str, APICircuitBreaker] = {}
_registry_lock = threading.Lock()

# APIs con umbrales personalizados
_API_CONFIG: Dict[str, Dict] = {
    'virustotal':        {'fail_threshold': 3, 'timeout': 120},
    'abuseipdb':         {'fail_threshold': 3, 'timeout': 120},
    'greynoise':         {'fail_threshold': 5, 'timeout': 60},
    'shodan':            {'fail_threshold': 3, 'timeout': 180},
    'otx':               {'fail_threshold': 5, 'timeout': 60},
    'threatfox':         {'fail_threshold': 5, 'timeout': 60},
    'urlhaus':           {'fail_threshold': 5, 'timeout': 60},
    'malwarebazaar':     {'fail_threshold': 5, 'timeout': 60},
    'hybrid_analysis':   {'fail_threshold': 3, 'timeout': 120},
    'securitytrails':    {'fail_threshold': 3, 'timeout': 300},  # API costosa — timeout largo
    'google_safebrowsing': {'fail_threshold': 5, 'timeout': 60},
    'criminal_ip':       {'fail_threshold': 3, 'timeout': 120},
    'pulsedive':         {'fail_threshold': 5, 'timeout': 60},
    'urlscan':           {'fail_threshold': 5, 'timeout': 60},
    'shodan_internetdb': {'fail_threshold': 5, 'timeout': 30},
    'ip_api':            {'fail_threshold': 5, 'timeout': 30},
    'ipinfo':            {'fail_threshold': 5, 'timeout': 60},
    'censys':            {'fail_threshold': 3, 'timeout': 180},
}


def get_circuit_breaker(api_name: str) -> APICircuitBreaker:
    """
    Retorna (o crea) el circuit breaker para la API dada.
    Thread-safe — usa el registro global.
    """
    with _registry_lock:
        if api_name not in _circuit_breakers:
            cfg = _API_CONFIG.get(api_name, {})
            _circuit_breakers[api_name] = APICircuitBreaker(
                api_name=api_name,
                fail_threshold=cfg.get('fail_threshold', 3),
                timeout=cfg.get('timeout', 60),
            )
        return _circuit_breakers[api_name]


def get_all_circuit_statuses() -> Dict[str, Dict]:
    """Retorna el estado de todos los circuit breakers (para el health check)."""
    with _registry_lock:
        return {name: cb.get_status() for name, cb in _circuit_breakers.items()}


def call_with_circuit_breaker(api_name: str, func, *args, **kwargs):
    """
    Helper: ejecuta `func(*args, **kwargs)` protegido por el circuit breaker.

    Si el circuito está OPEN, retorna {'error': 'circuit open', 'circuit_state': 'OPEN'}.
    Si la llamada falla (excepción), registra el fallo y relanza la excepción.

    Uso:
        result = call_with_circuit_breaker('virustotal', vt_client.check_ip, ip)
    """
    cb = get_circuit_breaker(api_name)
    if not cb.allow_request():
        logger.debug(f"[Circuit:{api_name}] Request blocked — circuit is OPEN")
        return {'error': 'service temporarily unavailable', 'circuit_state': 'OPEN'}

    try:
        result = func(*args, **kwargs)
        # Si el cliente retorna un dict con 'error' (fallo soft), cuenta como fallo
        if isinstance(result, dict) and 'error' in result:
            cb.record_failure()
        else:
            cb.record_success()
        return result
    except Exception as exc:
        cb.record_failure()
        raise
