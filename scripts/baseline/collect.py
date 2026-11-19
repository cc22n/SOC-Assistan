"""
Paso 3 de la línea base: consulta las APIs REALES para cada IOC del dataset y congela las respuestas.

  * Usa la estrategia por defecto de cada tipo (`LLMOrchestrator.strategies`), SIN planificador LLM: reproducible.
  * Guarda en tests/fixtures/baseline/snapshots.json -> sirven luego como fixtures con respuestas REALES
    (regla de CLAUDE.md) y permiten reevaluar cambios del scoring sin volver a gastar cuota de APIs.
  * Reanuda: salta los IOCs ya guardados.  Espera entre IOCs para no pasar el límite de VirusTotal (4/min).

Uso:  python scripts/baseline/collect.py            (todo el dataset)
      python scripts/baseline/collect.py --limit 3  (prueba)
      python scripts/baseline/collect.py --add-api threatfox --types ip,domain
          -> AÑADE esa API a los snapshots ya guardados (no repite las demás); sirve para evaluar una API nueva
"""
import argparse
import json
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / '.env')

HERE = Path(__file__).parent
OUT = ROOT / 'tests' / 'fixtures' / 'baseline' / 'snapshots.json'
VT_PAUSE = 16          # s entre IOCs que consultan VirusTotal (free: 4 peticiones/min)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--limit', type=int, default=0)
    ap.add_argument('--add-api', default='', help='añade solo esta API a los snapshots existentes')
    ap.add_argument('--types', default='', help='con --add-api: tipos separados por coma (ip,domain,...)')
    args = ap.parse_args()

    from app import create_app
    from app.services.llm_orchestrator import LLMOrchestrator
    app = create_app()
    dataset = json.loads((HERE / 'dataset.json').read_text(encoding='utf-8'))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    snaps = json.loads(OUT.read_text(encoding='utf-8')) if OUT.exists() else {}

    with app.app_context():
        orch = LLMOrchestrator()
        orch._initialize_clients()
        assert orch.api_clients, 'sin clientes de API (¿contexto de app?)'
        done = 0
        if args.add_api:
            tipos = set(filter(None, args.types.split(','))) or {'ip', 'domain', 'url', 'hash'}
            for row in dataset:
                key = f"{row['type']}:{row['value']}"
                if row['type'] not in tipos or key not in snaps or args.add_api in snaps[key]['api_results']:
                    continue
                res = orch._execute_apis(row['value'], row['type'], [args.add_api])
                snaps[key]['api_results'].update(res)
                if args.add_api not in snaps[key]['apis']:
                    snaps[key]['apis'].append(args.add_api)
                OUT.write_text(json.dumps(snaps, indent=1, ensure_ascii=False, default=str), encoding='utf-8')
                r = res.get(args.add_api, {})
                print(f"{key[:60]:60s} {'ERROR ' + str(r.get('error')) if 'error' in r else 'found=' + str(r.get('found'))}", flush=True)
            return
        for row in dataset:
            key = f"{row['type']}:{row['value']}"
            if key in snaps:
                continue
            apis = [a for a in orch.strategies[row['type']] if a in orch.api_clients]
            t0 = time.time()
            results = orch._execute_apis(row['value'], row['type'], apis)
            snaps[key] = {'ioc': row['value'], 'type': row['type'], 'apis': apis,
                          'collected_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                          'api_results': results}
            OUT.write_text(json.dumps(snaps, indent=1, ensure_ascii=False, default=str), encoding='utf-8')
            ok = sum(1 for r in results.values() if isinstance(r, dict) and 'error' not in r)
            print(f"[{len(snaps):3d}/{len(dataset)}] {key[:70]:70s} {ok}/{len(apis)} ok  {time.time()-t0:4.1f}s", flush=True)
            done += 1
            if args.limit and done >= args.limit:
                break
            if 'virustotal' in apis:
                time.sleep(VT_PAUSE)


main()
