"""
SOC Agent - Load & Stress Engineering Benchmark Suite
Especialista: load-stress-engineer

Este script ejecuta mediciones empíricas de:
1. Saturación de ThreadPoolExecutor en async_executor.py (max_workers=10 compartidos para 20 APIs)
2. Complejidad algorítmica O(N^2) en mitre_service.py (_parse_malware_mappings)
3. Problema de N+1 queries en _get_related_iocs y endpoint /search
4. Fuga de memoria por alta cardinalidad en _endpoint_metrics (app/utils/metrics.py)
5. Simulación de los 5 Escenarios de Carga (Smoke, Load, Stress, Spike, Soak)
"""
import os
import sys
import time
import math
import asyncio
import statistics
import threading
from typing import Dict, List, Any, Tuple
from concurrent.futures import ThreadPoolExecutor

# Configurar entorno de pruebas
os.environ['FLASK_ENV'] = 'testing'
os.environ['SECRET_KEY'] = 'stress-test-secret-key-1234567890abcdef'
os.environ['REDIS_URL'] = os.environ.get('REDIS_URL', 'redis://127.0.0.1:6379/0')
os.environ['DATABASE_URL'] = os.environ.get(
    'TEST_DATABASE_URL',
    'postgresql://soc_admin:1234@127.0.0.1:5432/soc_agent_test?client_encoding=utf8'
)

# ==============================================================================
# 1. BENCHMARK: ThreadPoolExecutor SATURATION (async_executor.py)
# ==============================================================================

def benchmark_threadpool_saturation():
    print("\n" + "="*70)
    print(" [1/5] BENCHMARK: ThreadPoolExecutor (max_workers=10 vs 20 APIs)")
    print("="*70)

    # Simular una llamada de API mockeada con latencia realista de 150ms
    def mock_api_call(api_name: str, delay: float = 0.15):
        time.sleep(delay)
        return {"api": api_name, "status": "ok"}

    NUM_APIS = 19
    apis = [f"api_{i}" for i in range(NUM_APIS)]

    for pool_size in [10, 20]:
        print(f"\n--- Evaluando ThreadPoolExecutor con max_workers={pool_size} ---")
        executor = ThreadPoolExecutor(max_workers=pool_size, thread_name_prefix='test-worker')

        async def run_single_ioc_analysis():
            loop = asyncio.get_event_loop()
            t0 = time.perf_counter()
            tasks = [
                loop.run_in_executor(executor, mock_api_call, api)
                for api in apis
            ]
            await asyncio.gather(*tasks)
            return (time.perf_counter() - t0) * 1000

        for concurrency in [1, 2, 5]:
            # Ejecutar 'concurrency' análisis de IOC simultáneos
            async def run_batch():
                return await asyncio.gather(*[run_single_ioc_analysis() for _ in range(concurrency)])

            latencies = asyncio.run(run_batch())
            p50 = statistics.median(latencies)
            p95 = sorted(latencies)[math.floor(len(latencies) * 0.95)] if len(latencies) > 1 else latencies[0]
            max_lat = max(latencies)
            total_tasks = concurrency * NUM_APIS
            print(f"  > Concurrencia: {concurrency} IOCs ({total_tasks} API tasks) | Latencia p50: {p50:.2f} ms | Max: {max_lat:.2f} ms")

        executor.shutdown(wait=True)

# ==============================================================================
# 2. BENCHMARK: MITRE STIX O(N^2) COMPLEXITY
# ==============================================================================

def benchmark_mitre_stix_complexity():
    print("\n" + "="*70)
    print(" [2/5] BENCHMARK: Complejidad O(N^2) en mitre_service.py")
    print("="*70)

    # Generar objetos STIX sintéticos
    def generate_stix_objects(num_objects: int):
        num_software = max(10, num_objects // 20)
        num_techniques = max(50, num_objects // 10)
        num_relationships = max(50, num_objects // 5)

        objects = []
        for i in range(num_software):
            objects.append({
                'type': 'malware',
                'id': f'malware--{i}',
                'name': f'Malware_{i}',
                'external_references': [{'source_name': 'mitre-attack', 'external_id': f'S{i:04d}'}]
            })
        for i in range(num_techniques):
            objects.append({
                'type': 'attack-pattern',
                'id': f'attack-pattern--{i}',
                'name': f'Technique_{i}',
                'external_references': [{'source_name': 'mitre-attack', 'external_id': f'T1{i:03d}'}]
            })
        for i in range(num_relationships):
            objects.append({
                'type': 'relationship',
                'relationship_type': 'uses',
                'source_ref': f'malware--{i % num_software}',
                'target_ref': f'attack-pattern--{i % num_techniques}'
            })
        return objects

    for size in [500, 1500, 3000, 6000]:
        stix_objects = generate_stix_objects(size)

        # Algoritmo ACTUAL (O(N^2)): doble bucle anidado
        t0 = time.perf_counter()
        software = {obj['id']: {'name': obj.get('name'), 'techniques': []}
                    for obj in stix_objects if obj.get('type') in ('malware', 'tool')}
        for obj in stix_objects:
            if obj.get('type') == 'relationship' and obj.get('relationship_type') == 'uses':
                source = obj.get('source_ref', '')
                target = obj.get('target_ref', '')
                if source in software and target.startswith('attack-pattern'):
                    for inner in stix_objects:
                        if inner.get('id') == target and inner.get('type') == 'attack-pattern':
                            for ref in inner.get('external_references', []):
                                if ref.get('source_name') == 'mitre-attack':
                                    software[source]['techniques'].append(ref['external_id'])
                                    break
                            break
        t_n2 = (time.perf_counter() - t0) * 1000

        # Algoritmo OPTIMIZADO (O(N)): diccionario indexado
        t0 = time.perf_counter()
        tech_map = {}
        for obj in stix_objects:
            if obj.get('type') == 'attack-pattern':
                for ref in obj.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        tech_map[obj['id']] = ref['external_id']
                        break

        software_opt = {obj['id']: {'name': obj.get('name'), 'techniques': []}
                        for obj in stix_objects if obj.get('type') in ('malware', 'tool')}
        for obj in stix_objects:
            if obj.get('type') == 'relationship' and obj.get('relationship_type') == 'uses':
                source = obj.get('source_ref', '')
                target = obj.get('target_ref', '')
                if source in software_opt and target in tech_map:
                    software_opt[source]['techniques'].append(tech_map[target])
        t_n1 = (time.perf_counter() - t0) * 1000

        speedup = t_n2 / t_n1 if t_n1 > 0 else float('inf')
        print(f"  Objetos STIX: {size:5d} | Actual O(N^2): {t_n2:8.2f} ms | Optimizado O(N): {t_n1:6.2f} ms | Aceleración: {speedup:6.1f}x")

# ==============================================================================
# 3. BENCHMARK: N+1 QUERIES (_get_related_iocs & /search)
# ==============================================================================

def benchmark_n_plus_one():
    print("\n" + "="*70)
    print(" [3/5] BENCHMARK: Problema de N+1 Queries en Postgres")
    print("="*70)

    from app import create_app, db
    from app.models.ioc import User, IOC, IOCAnalysis
    from sqlalchemy import event
    from sqlalchemy.orm import joinedload

    app = create_app('testing')
    with app.app_context():
        # Limpiar y poblar datos sintéticos
        db.create_all()
        # Verificar o crear usuario analista
        user = User.query.filter_by(username='bench_analyst').first()
        if not user:
            user = User(username='bench_analyst', email='bench@soc.local', role='analyst')
            user.set_password('Secret123!')
            db.session.add(user)
            db.session.commit()
        user_id = user.id

        # Insertar 40 IOCs y Análisis
        current_count = IOCAnalysis.query.filter_by(user_id=user_id).count()
        if current_count < 40:
            for i in range(40):
                ioc_val = f"192.168.10.{i+1}"
                ioc = IOC.query.filter_by(value=ioc_val).first()
                if not ioc:
                    ioc = IOC(value=ioc_val, ioc_type='ip')
                    db.session.add(ioc)
                    db.session.flush()
                analysis = IOCAnalysis(
                    ioc_id=ioc.id,
                    user_id=user_id,
                    risk_level='HIGH',
                    confidence_score=85,
                    virustotal_data={'malware_families': ['Emotet', 'CobaltStrike']} if i % 2 == 0 else {},
                    mitre_techniques=['T1059.001'] if i % 2 == 0 else []
                )
                db.session.add(analysis)
            db.session.commit()

        # Contador de consultas SQL
        sql_count = 0
        @event.listens_for(db.engine, "before_cursor_execute")
        def count_queries(conn, cursor, statement, parameters, context, executemany):
            nonlocal sql_count
            sql_count += 1

        # Test A: /search endpoint (Lazy load vs Joinedload)
        print("\n--- Endpoint /search (20 filas devueltas) ---")
        sql_count = 0
        t0 = time.perf_counter()
        analyses_lazy = IOCAnalysis.query.join(IOC).filter(
            IOC.value.contains("192.168", autoescape=True)
        ).order_by(IOCAnalysis.created_at.desc()).limit(20).all()
        # Simular Jinja accediendo a analysis.ioc.value
        values_lazy = [a.ioc.value for a in analyses_lazy]
        t_lazy = (time.perf_counter() - t0) * 1000
        queries_lazy = sql_count

        sql_count = 0
        t0 = time.perf_counter()
        analyses_eager = IOCAnalysis.query.join(IOC).options(
            joinedload(IOCAnalysis.ioc)
        ).filter(
            IOC.value.contains("192.168", autoescape=True)
        ).order_by(IOCAnalysis.created_at.desc()).limit(20).all()
        values_eager = [a.ioc.value for a in analyses_eager]
        t_eager = (time.perf_counter() - t0) * 1000
        queries_eager = sql_count

        print(f"  > Actual (Lazy Load):    {queries_lazy} consultas SQL ejecutadas | Tiempo: {t_lazy:.2f} ms")
        print(f"  > Optimizado (Joinedload): {queries_eager} consultas SQL ejecutadas | Tiempo: {t_eager:.2f} ms")
        print(f"  > Reducción de queries:  -{(1 - queries_eager/queries_lazy)*100:.1f}%")

        # Test B: _get_related_iocs
        print("\n--- Función _get_related_iocs (Grafo de Correlación) ---")
        from app.services.llm_orchestrator import LLMOrchestrator
        orchestrator = LLMOrchestrator()

        sample_analysis = {
            'api_results': {'virustotal': {'malware_families': ['Emotet']}},
            'mitre_techniques': ['T1059.001']
        }

        sql_count = 0
        t0 = time.perf_counter()
        related = orchestrator._get_related_iocs("192.168.10.1", sample_analysis, user_id, limit=5)
        t_corr = (time.perf_counter() - t0) * 1000
        print(f"  > Queries SQL ejecutadas en _get_related_iocs: {sql_count} consultas SQL")
        print(f"  > Tiempo total de correlación: {t_corr:.2f} ms | Correlacionados: {len(related) if related else 0}")

# ==============================================================================
# 4. BENCHMARK: MÉTRICAS Y ALTA CARDINALIDAD (_endpoint_metrics)
# ==============================================================================

def benchmark_metrics_cardinality():
    print("\n" + "="*70)
    print(" [4/5] BENCHMARK: Fuga de Memoria por Alta Cardinalidad en Métricas")
    print("="*70)

    from app.utils.metrics import record_request_time, _endpoint_metrics

    initial_keys = len(_endpoint_metrics)
    print(f"  Series registradas inicialmente: {initial_keys}")

    # Simular escaneo de 1,000 URLs con IDs dinámicos (/ioc/<id>, /sessions/<id>)
    for i in range(1, 1001):
        record_request_time(f"/ioc/{i}/whitelist", latency_ms=12.5, success=True)
        record_request_time(f"/sessions/{i}/messages", latency_ms=15.0, success=True)

    final_keys = len(_endpoint_metrics)
    print(f"  Series registradas tras escaneo: {final_keys} (+{final_keys - initial_keys} nuevas series)")
    print(f"  Diagnóstico: Inyección de path crudo en vez de endpoint genera fugas de memoria O(N) permanentes.")

# ==============================================================================
# 5. BENCHMARK: LOS 5 ESCENARIOS DE CARGA (HTTP / ASYNCIO + HTTPX)
# ==============================================================================

def run_http_benchmark_scenarios():
    print("\n" + "="*70)
    print(" [5/5] BENCHMARK DE CARGA Y CONCURRENCIA: LOS 5 ESCENARIOS")
    print("="*70)

    import httpx
    from waitress import create_server
    from app import create_app

    # Iniciar servidor WSGI local en thread de fondo para medir con sockets reales
    app = create_app('testing')
    # Configurar waitress con 3 threads para emular exactamente los 3 workers sync de Gunicorn
    server = create_server(app, host='127.0.0.1', port=5005, threads=3)
    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()
    time.sleep(1.0) # Esperar a que el servidor esté listo

    base_url = "http://127.0.0.1:5005"

    async def execute_scenario(name: str, concurrency: int, duration_sec: float, endpoint: str = "/api/v2/health"):
        print(f"\n>>> Iniciando Escenario: {name} (Concurrencia: {concurrency}, Duración: {duration_sec}s, Endpoint: {endpoint})")
        sem = asyncio.Semaphore(concurrency)
        latencies = []
        errors = 0
        total_requests = 0
        start_time = time.monotonic()

        async with httpx.AsyncClient(timeout=10.0) as client:
            async def worker():
                nonlocal errors, total_requests
                while time.monotonic() - start_time < duration_sec:
                    async with sem:
                        req_t0 = time.perf_counter()
                        try:
                            resp = await client.get(f"{base_url}{endpoint}")
                            req_time = (time.perf_counter() - req_t0) * 1000
                            latencies.append(req_time)
                            total_requests += 1
                            if resp.status_code >= 400:
                                errors += 1
                        except Exception:
                            errors += 1
                            total_requests += 1
                        # Pequeño think time
                        await asyncio.sleep(0.01)

            tasks = [asyncio.create_task(worker()) for _ in range(concurrency)]
            await asyncio.gather(*tasks)

        elapsed = time.monotonic() - start_time
        rps = total_requests / elapsed if elapsed > 0 else 0
        error_rate = (errors / total_requests * 100) if total_requests > 0 else 0

        if latencies:
            latencies.sort()
            n = len(latencies)
            p50 = latencies[int(n * 0.50)]
            p95 = latencies[min(int(n * 0.95), n - 1)]
            p99 = latencies[min(int(n * 0.99), n - 1)]
            max_lat = latencies[-1]
        else:
            p50 = p95 = p99 = max_lat = 0

        print(f"  Resultados [{name}]:")
        print(f"    Total Peticiones: {total_requests} | RPS: {rps:.1f} req/s | Tasa de Error: {error_rate:.2f}%")
        print(f"    Latencia p50: {p50:.2f} ms | p95: {p95:.2f} ms | p99: {p99:.2f} ms | Max: {max_lat:.2f} ms")
        return {
            "scenario": name,
            "concurrency": concurrency,
            "rps": round(rps, 1),
            "p50": round(p50, 2),
            "p95": round(p95, 2),
            "p99": round(p99, 2),
            "max": round(max_lat, 2),
            "error_rate": round(error_rate, 2),
            "total": total_requests
        }

    scenarios = [
        ("1. Smoke Test", 2, 10.0, "/api/v2/health"),
        ("2. Load Test", 20, 15.0, "/api/v2/health"),
        ("3. Stress Peak", 60, 15.0, "/api/v2/health"),
        ("4. Spike Burst", 100, 10.0, "/api/v2/health"),
        ("5. Soak Test", 15, 20.0, "/api/v2/health"),
    ]

    results = []
    for sc in scenarios:
        res = asyncio.run(execute_scenario(sc[0], sc[1], sc[2], sc[3]))
        results.append(res)

    print("\n" + "="*70)
    print(" RESUMEN GENERAL DE LOS 5 ESCENARIOS DE CARGA")
    print("="*70)
    print(f"{'Escenario':<18} | {'Conc':<5} | {'RPS':<8} | {'p50 (ms)':<9} | {'p95 (ms)':<9} | {'p99 (ms)':<9} | {'% Error':<7}")
    print("-" * 75)
    for r in results:
        print(f"{r['scenario']:<18} | {r['concurrency']:<5} | {r['rps']:<8.1f} | {r['p50']:<9.2f} | {r['p95']:<9.2f} | {r['p99']:<9.2f} | {r['error_rate']:<7.2f}%")


if __name__ == '__main__':
    benchmark_threadpool_saturation()
    benchmark_mitre_stix_complexity()
    benchmark_n_plus_one()
    benchmark_metrics_cardinality()
    run_http_benchmark_scenarios()
