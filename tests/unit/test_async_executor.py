"""
Tests para app/services/async_executor.py -- sin cobertura directa hasta
ahora, pese a ser el UNICO punto real de despacho hacia las APIs de threat
intel. Cubre _call_with_instrumentation (circuit breaker + metricas
aplicados al path real, antes solo los usaba UnifiedThreatIntelClient,
dead code) y que execute_apis_parallel/_fallback_sequential lo respetan.
"""
import pytest
from unittest.mock import MagicMock


@pytest.fixture(scope='function')
def app_ctx(app):
    """Push un app context -- get_circuit_breaker/record_api_latency no
    necesitan Flask, pero mantiene el patron del resto de la suite."""
    with app.app_context():
        yield


# ==============================================================================
# _call_with_instrumentation
# ==============================================================================

class TestCallWithInstrumentation:

    def test_successful_call_returns_result_and_records_success(self, app_ctx):
        from app.services.async_executor import _call_with_instrumentation
        from app.utils.circuit_breaker import get_circuit_breaker

        method = MagicMock(return_value={'found': True, 'malicious': 0})
        result = _call_with_instrumentation('test_ok_api', method)

        assert result == {'found': True, 'malicious': 0}
        method.assert_called_once()
        assert get_circuit_breaker('test_ok_api').state.value == 'CLOSED'

    def test_soft_error_dict_counts_as_failure(self, app_ctx):
        from app.services.async_executor import _call_with_instrumentation
        from app.utils.circuit_breaker import get_circuit_breaker, _API_CONFIG

        _API_CONFIG['test_soft_error_api'] = {'fail_threshold': 2, 'timeout': 60}
        method = MagicMock(return_value={'error': 'boom'})

        _call_with_instrumentation('test_soft_error_api', method)
        _call_with_instrumentation('test_soft_error_api', method)

        assert get_circuit_breaker('test_soft_error_api').state.value == 'OPEN'

    def test_exception_propagates_and_counts_as_failure(self, app_ctx):
        from app.services.async_executor import _call_with_instrumentation
        from app.utils.circuit_breaker import get_circuit_breaker, _API_CONFIG

        _API_CONFIG['test_exc_api'] = {'fail_threshold': 1, 'timeout': 60}
        method = MagicMock(side_effect=RuntimeError('connection refused'))

        with pytest.raises(RuntimeError):
            _call_with_instrumentation('test_exc_api', method)

        assert get_circuit_breaker('test_exc_api').state.value == 'OPEN'

    def test_open_circuit_blocks_without_calling_method(self, app_ctx):
        from app.services.async_executor import _call_with_instrumentation
        from app.utils.circuit_breaker import get_circuit_breaker, _API_CONFIG

        _API_CONFIG['test_blocked_api'] = {'fail_threshold': 1, 'timeout': 60}
        get_circuit_breaker('test_blocked_api').record_failure()  # abre el circuito

        method = MagicMock(return_value={'found': True})
        result = _call_with_instrumentation('test_blocked_api', method)

        assert result == {'error': 'service temporarily unavailable', 'circuit_state': 'OPEN'}
        method.assert_not_called()

    def test_records_latency_metrics(self, app_ctx):
        from app.services.async_executor import _call_with_instrumentation
        from app.utils.metrics import get_metrics_summary

        method = MagicMock(return_value={'found': True})
        _call_with_instrumentation('test_metrics_dispatch_api', method)

        summary = get_metrics_summary()
        assert summary['apis']['test_metrics_dispatch_api']['count'] == 1


# ==============================================================================
# execute_apis_parallel -- integracion end-to-end del path real
# ==============================================================================

class TestExecuteApisParallelCircuitBreaker:

    def test_repeated_failures_open_circuit_and_block_next_call(self, app_ctx):
        """Tras fail_threshold fallos consecutivos de la misma api_name,
        una llamada posterior ya no invoca al cliente -- queda bloqueada
        por el circuit breaker."""
        from app.services.async_executor import execute_apis_parallel
        from app.utils.circuit_breaker import _API_CONFIG

        _API_CONFIG['test_flaky_api'] = {'fail_threshold': 2, 'timeout': 60}

        client = MagicMock()
        client.check_ip.return_value = {'error': 'timeout'}
        api_clients = {'test_flaky_api': client}

        # _resolve_method no conoce 'test_flaky_api': parcheamos el mapa
        import app.services.async_executor as ae
        original_resolve = ae._resolve_method
        ae._resolve_method = lambda api_name, c, ioc, ioc_type: (
            (lambda: c.check_ip(ioc)) if api_name == 'test_flaky_api' else original_resolve(api_name, c, ioc, ioc_type)
        )
        try:
            execute_apis_parallel('1.2.3.4', 'ip', ['test_flaky_api'], api_clients)
            execute_apis_parallel('1.2.3.4', 'ip', ['test_flaky_api'], api_clients)
            assert client.check_ip.call_count == 2

            results = execute_apis_parallel('1.2.3.4', 'ip', ['test_flaky_api'], api_clients)
            assert client.check_ip.call_count == 2  # no crecio: circuito abierto
            assert results['test_flaky_api']['circuit_state'] == 'OPEN'
        finally:
            ae._resolve_method = original_resolve
