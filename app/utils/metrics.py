"""
SOC Agent - Métricas de Performance en Memoria
Fase 5 - T5C-01

Recolecta tiempos de respuesta por endpoint y por API de TI.
Calcula P50/P95/P99 sobre una ventana deslizante de las últimas N muestras.

No requiere dependencias externas (sin Prometheus, sin StatsD).
Thread-safe mediante threading.Lock.

Uso:
    from app.utils.metrics import record_request_time, record_api_latency, get_metrics_summary

    # En after_request:
    record_request_time(endpoint='/api/v2/analyze/enhanced', latency_ms=1234.5, success=True)

    # En el cliente de API:
    record_api_latency(api_name='virustotal', latency_ms=450.2, success=True)
"""
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Any, Dict, List

# Ventana máxima de muestras por serie (evita crecer sin límite)
_MAX_SAMPLES = 500


class _TimeSeries:
    """Ventana deslizante de muestras con percentiles."""

    def __init__(self, max_samples: int = _MAX_SAMPLES) -> None:
        self._latencies: deque = deque(maxlen=max_samples)
        self._errors: int = 0
        self._total: int = 0
        self._lock = threading.Lock()

    def record(self, latency_ms: float, success: bool) -> None:
        with self._lock:
            self._latencies.append(latency_ms)
            self._total += 1
            if not success:
                self._errors += 1

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            samples = sorted(self._latencies)
            n = len(samples)
            if n == 0:
                return {
                    'count': 0, 'errors': self._errors,
                    'p50': None, 'p95': None, 'p99': None,
                    'avg': None, 'min': None, 'max': None,
                    'error_rate': 0.0,
                }

            def percentile(p):
                idx = int(n * p / 100)
                return round(samples[min(idx, n - 1)], 2)

            return {
                'count': self._total,
                'errors': self._errors,
                'p50': percentile(50),
                'p95': percentile(95),
                'p99': percentile(99),
                'avg': round(sum(samples) / n, 2),
                'min': round(samples[0], 2),
                'max': round(samples[-1], 2),
                'error_rate': round(self._errors / self._total * 100, 2) if self._total > 0 else 0.0,
            }


# =============================================================================
# REGISTROS GLOBALES
# =============================================================================

_endpoint_metrics: Dict[str, _TimeSeries] = defaultdict(_TimeSeries)
_api_metrics: Dict[str, _TimeSeries] = defaultdict(_TimeSeries)
_registry_lock = threading.Lock()

# Timestamp de inicio (para uptime en health check)
_start_time = datetime.utcnow()


def record_request_time(endpoint: str, latency_ms: float, success: bool = True) -> None:
    """Registra la latencia de un endpoint HTTP."""
    with _registry_lock:
        _endpoint_metrics[endpoint].record(latency_ms, success)


def record_api_latency(api_name: str, latency_ms: float, success: bool = True) -> None:
    """Registra la latencia de una llamada a API de TI."""
    with _registry_lock:
        _api_metrics[api_name].record(latency_ms, success)


def get_metrics_summary() -> Dict[str, Any]:
    """
    Retorna el resumen de métricas para el endpoint /api/v2/health/metrics.
    Incluye P50/P95/P99 por endpoint y top 5 APIs más lentas.
    """
    with _registry_lock:
        endpoint_stats = {ep: ts.stats() for ep, ts in _endpoint_metrics.items()}
        api_stats = {api: ts.stats() for api, ts in _api_metrics.items()}

    # Top 5 APIs más lentas por P95
    top_slow = sorted(
        [(name, s) for name, s in api_stats.items() if s['p95'] is not None],
        key=lambda x: x[1]['p95'],
        reverse=True
    )[:5]

    # Top 5 APIs con mayor tasa de error
    top_errors = sorted(
        [(name, s) for name, s in api_stats.items() if s['count'] > 0],
        key=lambda x: x[1]['error_rate'],
        reverse=True
    )[:5]

    uptime_seconds = (datetime.utcnow() - _start_time).total_seconds()

    return {
        'uptime_seconds': round(uptime_seconds),
        'endpoints': endpoint_stats,
        'apis': api_stats,
        'top_slow_apis': [{'api': n, **s} for n, s in top_slow],
        'top_error_apis': [{'api': n, **s} for n, s in top_errors],
        'collected_at': datetime.utcnow().isoformat(),
    }
