"""
Paso 4 de la línea base: mide el scoring ACTUAL contra el dataset etiquetado, offline (no llama a ninguna API).

Entrada : scripts/baseline/dataset.json + tests/fixtures/baseline/snapshots.json  (respuestas reales congeladas)
Salida  : scripts/baseline/REPORT.md  y  scripts/baseline/results.json

Qué mide (solo la parte DETERMINISTA del análisis: `_calculate_enhanced_score` + `_determine_risk_level`; el
score no usa el texto del LLM, ver llm_orchestrator.py):
  * Distribución de niveles de riesgo por etiqueta y matriz de confusión a dos umbrales de alerta.
  * Precisión / recall / tasa de falsos positivos.
  * 'leave-source-out': mismo cálculo SIN las APIs que sirvieron para etiquetar (abuse.ch), para no medir
    una tautología.
  * Cobertura de APIs: tasa de éxito, errores y respuestas '200 sin campos útiles' (fallo silencioso).
  * Cuántos puntos de un IOC limpio vienen solo de "la API respondió" (+5 por API sin error).
"""
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / '.env')
HERE = Path(__file__).parent
TAG = os.environ.get('BASELINE_TAG', '')      # '' = la línea base original (2026-11-18); '_2026-11-19' = el repaso
SNAP = ROOT / 'tests' / 'fixtures' / 'baseline' / f'snapshots{TAG}.json'

LEVELS = ['LIMPIO', 'BAJO', 'MEDIO', 'ALTO', 'CRÍTICO']
# APIs que comparten fuente con la etiqueta (abuse.ch) -> se excluyen en leave-source-out
SOURCE_APIS = {'threatfox': {'threatfox', 'urlhaus', 'malwarebazaar'}, 'urlhaus': {'threatfox', 'urlhaus', 'malwarebazaar'},
               'malwarebazaar': {'threatfox', 'urlhaus', 'malwarebazaar'}}


def pct(a, b):
    return f'{100 * a / b:.0f}%' if b else 'n/a'


def main():
    from app import create_app
    from app.services.llm_orchestrator import LLMOrchestrator
    app = create_app()
    dataset = json.loads((HERE / f'dataset{TAG}.json').read_text(encoding='utf-8'))
    snaps = json.loads(SNAP.read_text(encoding='utf-8'))

    with app.app_context():
        orch = LLMOrchestrator()
        rows = []
        for d in dataset:
            s = snaps.get(f"{d['type']}:{d['value']}")
            if not s:
                continue
            res = s['api_results']
            score = orch._calculate_enhanced_score(res, {})
            # leave-source-out
            excl = SOURCE_APIS.get(d['label_source'], set())
            res_los = {k: v for k, v in res.items() if k not in excl}
            score_los = orch._calculate_enhanced_score(res_los, {})
            presence = 5 * sum(1 for r in res.values() if 'error' not in r)
            rows.append({**d, 'score': score, 'level': orch._determine_risk_level(score),
                         'score_los': score_los, 'level_los': orch._determine_risk_level(score_los),
                         'presence_points': presence, 'n_ok': sum(1 for r in res.values() if 'error' not in r),
                         'n_apis': len(res)})

    L = []
    w = L.append
    w('# Línea base de calidad del análisis (fase 0.2 de PLAN-FUSION)\n')
    w(f'IOCs evaluados: **{len(rows)}** de {len(dataset)} del dataset. Respuestas reales congeladas en '
      f'`tests/fixtures/baseline/snapshots{TAG}.json`. Se mide el scoring determinista actual '
      f'(`_calculate_enhanced_score`); el texto del LLM no entra en el score.\n')
    cnt = Counter(r['label'] for r in rows)
    w('Composición: ' + ', '.join(f'{k}={v}' for k, v in cnt.items()) + '\n')

    def table_levels(key, title):
        w(f'### {title}\n')
        w('| etiqueta | ' + ' | '.join(LEVELS) + ' | n |')
        w('|---|' + '---|' * (len(LEVELS) + 1))
        for lab in ('malicious', 'benign', 'ambiguous'):
            sub = [r for r in rows if r['label'] == lab]
            c = Counter(r[key] for r in sub)
            w(f'| {lab} | ' + ' | '.join(str(c.get(l, 0)) for l in LEVELS) + f' | {len(sub)} |')
        w('')

    table_levels('level', 'Nivel de riesgo asignado (análisis completo)')
    table_levels('level_los', 'Nivel de riesgo SIN las APIs de la fuente de la etiqueta (leave-source-out, solo maliciosos son afectados)')

    def metrics(key, thr_names, title):
        w(f'### {title}\n')
        w('| tipo | recall maliciosos | falsos positivos (benignos) | precisión | n mal / n ben |')
        w('|---|---|---|---|---|')
        for t in ('ALL', 'ip', 'domain', 'url', 'hash'):
            sel = [r for r in rows if t == 'ALL' or r['type'] == t]
            mal = [r for r in sel if r['label'] == 'malicious']
            ben = [r for r in sel if r['label'] == 'benign']
            tp = sum(r[key] in thr_names for r in mal)
            fp = sum(r[key] in thr_names for r in ben)
            w(f'| {t} | {pct(tp, len(mal))} ({tp}/{len(mal)}) | {pct(fp, len(ben))} ({fp}/{len(ben)}) | '
              f'{pct(tp, tp + fp)} | {len(mal)} / {len(ben)} |')
        w('')

    metrics('level', {'ALTO', 'CRÍTICO'}, 'Alerta = ALTO o CRÍTICO (score ≥ 50), análisis completo')
    metrics('level', {'MEDIO', 'ALTO', 'CRÍTICO'}, 'Alerta = MEDIO o peor (score ≥ 30), análisis completo')
    metrics('level_los', {'ALTO', 'CRÍTICO'}, 'Alerta = ALTO o CRÍTICO, SIN APIs de la fuente de la etiqueta')
    metrics('level_los', {'MEDIO', 'ALTO', 'CRÍTICO'}, 'Alerta = MEDIO o peor, SIN APIs de la fuente de la etiqueta')

    ben = [r for r in rows if r['label'] == 'benign']
    w('### Falsos positivos (benignos con nivel ≥ MEDIO)\n')
    fps = [r for r in ben if r['level'] in ('MEDIO', 'ALTO', 'CRÍTICO')]
    for r in sorted(fps, key=lambda r: -r['score']):
        w(f"- `{r['value'][:60]}` ({r['type']}, {r['note'] or r['category']}) score={r['score']} {r['level']} "
          f"(presencia {r['presence_points']})")
    if not fps:
        w('- ninguno')
    w('')
    w('### Falsos negativos (maliciosos con nivel ≤ BAJO, análisis completo)\n')
    fns = [r for r in rows if r['label'] == 'malicious' and r['level'] in ('LIMPIO', 'BAJO')]
    for r in fns:
        w(f"- `{r['value'][:70]}` ({r['type']}, {r['note']}) score={r['score']} {r['level']}  [{r['n_ok']}/{r['n_apis']} APIs ok]")
    if not fns:
        w('- ninguno')
    w('')
    amb = [r for r in rows if r['label'] == 'ambiguous']
    if amb:
        w('### Ambiguos (informativo, no puntúa)\n')
        for r in sorted(amb, key=lambda r: -r['score']):
            w(f"- `{r['value']}` ({r['category']}) score={r['score']} {r['level']}")
        w('')

    # cobertura de APIs
    snap_rows = [snaps[f"{d['type']}:{d['value']}"] for d in dataset if f"{d['type']}:{d['value']}" in snaps]
    stat = defaultdict(lambda: Counter())
    err_msgs = defaultdict(Counter)
    for s in snap_rows:
        for api, r in s['api_results'].items():
            if 'error' in r:
                stat[api]['error'] += 1
                err_msgs[api][str(r['error'])[:60]] += 1
            else:
                stat[api]['ok'] += 1
    w('### Cobertura de APIs (respuestas reales)\n')
    w('| API | ok | error | tasa de éxito | error más frecuente |')
    w('|---|---|---|---|---|')
    for api, c in sorted(stat.items(), key=lambda kv: kv[1]['ok'] / max(1, sum(kv[1].values()))):
        tot = c['ok'] + c['error']
        top = err_msgs[api].most_common(1)
        w(f"| {api} | {c['ok']} | {c['error']} | {pct(c['ok'], tot)} | {top[0][0] + f' (×{top[0][1]})' if top else ''} |")
    w('')

    # recall por fuente de la etiqueta: las INDEPENDIENTES de abuse.ch son las que miden recall real (sin circularidad)
    w('### Recall de maliciosos por fuente de la etiqueta (ALTO o peor | MEDIO o peor)\n')
    w('| fuente de la etiqueta | tipo | n | ALTO+ | MEDIO+ | independiente de abuse.ch |')
    w('|---|---|---|---|---|---|')
    for src in sorted({r['label_source'] for r in rows if r['label'] == 'malicious'}):
        sub = [r for r in rows if r['label'] == 'malicious' and r['label_source'] == src]
        hi = sum(r['level'] in ('ALTO', 'CRÍTICO') for r in sub)
        mid = sum(r['level'] in ('MEDIO', 'ALTO', 'CRÍTICO') for r in sub)
        indep = 'sí' if src in ('cins_army', 'emerging_threats', 'openphish') else 'no (circular)'
        w(f"| {src} | {sub[0]['type']} | {len(sub)} | {pct(hi, len(sub))} ({hi}) | {pct(mid, len(sub))} ({mid}) | {indep} |")
    w('')

    (HERE / f'REPORT{TAG}.md').write_text('\n'.join(L), encoding='utf-8')
    (HERE / f'results{TAG}.json').write_text(json.dumps(rows, indent=1, ensure_ascii=False), encoding='utf-8')
    print('\n'.join(L))


main()
