"""
Línea base de CVE (WP3 de PLAN-FUSION), en tres fases:

  python scripts/baseline/cve_baseline.py build      # arma scripts/baseline/cve_dataset.json (necesita red)
  python scripts/baseline/cve_baseline.py collect    # consulta las 4 APIs REALES -> tests/fixtures/baseline/cve_snapshots.json
                                                     #   (~10 min: NVD sin clave admite 5 peticiones / 30 s)
  python scripts/baseline/cve_baseline.py evaluate   # offline -> scripts/baseline/CVE_REPORT.md

Qué se mide y por qué así:
  * Etiqueta = pertenencia al catálogo CISA KEV ("explotado en la naturaleza"), que es la definición operativa de CVE
    peligroso. Pero el cliente de KEV acierta por construcción, así que la medida honesta es: ¿cuánto PREDICEN la
    pertenencia a KEV las demás señales (NVD/CVSS, EPSS, Exploit-DB)? ('leave-KEV-out').
  * LÍMITE: "no está en KEV" NO significa "no se explota": KEV es un catálogo incompleto. Los negativos son "sin
    explotación confirmada por CISA", no "inofensivos".
  * Grupo `ctid`: CVEs con mapeo MITRE curado (CTID), para medir cuánto acierta la heurística de técnicas sobre el vector CVSS.
"""
import csv
import io
import json
import random
import sys
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / '.env')
HERE = Path(__file__).parent
DATASET = HERE / 'cve_dataset.json'
SNAP = ROOT / 'tests' / 'fixtures' / 'baseline' / 'cve_snapshots.json'
KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
NVD_PAUSE = 7        # s entre peticiones a NVD sin clave (límite 5 por 30 s)
N_KEV, N_NEG_PER_YEAR, N_CTID = 25, 3, 40
rnd = random.Random(20261119)


def build():
    kev = requests.get(KEV_URL, timeout=60).json()['vulnerabilities']
    kev_ids = {v['cveID'] for v in kev}
    by_year = {}
    for v in kev:
        by_year.setdefault(int(v['cveID'].split('-')[1]), []).append(v['cveID'])
    years = sorted(y for y in by_year if 2012 <= y <= 2025)
    pos = []
    while len(pos) < N_KEV:                                   # reparto parejo por año
        for y in years:
            pool = [c for c in by_year[y] if c not in pos]
            if pool and len(pos) < N_KEV:
                pos.append(rnd.choice(pool))
    rows = [{'cve': c, 'label': 'kev', 'group': 'kev'} for c in pos]

    neg = []
    for y in range(2016, 2026):                               # ventana de 2 días de cada año; solo los que NVD ya puntuó
        r = requests.get(NVD, params={'pubStartDate': f'{y}-03-10T00:00:00.000', 'pubEndDate': f'{y}-03-12T00:00:00.000'}, timeout=90)
        time.sleep(NVD_PAUSE)
        if r.status_code != 200:
            print('NVD', y, r.status_code)
            continue
        pool = [v['cve']['id'] for v in r.json().get('vulnerabilities', [])
                if v['cve']['id'] not in kev_ids and v['cve'].get('metrics')]
        rnd.shuffle(pool)
        neg += pool[:N_NEG_PER_YEAR]
    rows += [{'cve': c, 'label': 'no_kev', 'group': 'no_kev'} for c in neg]

    raw = requests.get('https://raw.githubusercontent.com/center-for-threat-informed-defense/attack_to_cve/master/Att%26ckToCveMappings.csv', timeout=60).content.decode('utf-8-sig')
    ctid_ids = [r['CVE ID'] for r in csv.DictReader(io.StringIO(raw)) if r['CVE ID'] not in pos and r['CVE ID'] not in neg]
    rnd.shuffle(ctid_ids)
    rows += [{'cve': c, 'label': 'ctid', 'group': 'ctid'} for c in ctid_ids[:N_CTID]]
    DATASET.write_text(json.dumps(rows, indent=1), encoding='utf-8')
    from collections import Counter
    print(len(rows), 'CVEs ->', DATASET.name, dict(Counter(r['group'] for r in rows)))


def collect():
    from app import create_app
    from app.services.cve_clients import NVDClient, CISAKEVClient, EPSSClient, ExploitDBClient
    app = create_app()
    rows = json.loads(DATASET.read_text(encoding='utf-8'))
    snaps = json.loads(SNAP.read_text(encoding='utf-8')) if SNAP.exists() else {}
    with app.app_context():
        clients = {'nvd': NVDClient(), 'cisa_kev': CISAKEVClient(), 'epss': EPSSClient(), 'exploitdb': ExploitDBClient()}
        for i, row in enumerate(rows, 1):
            cve = row['cve']
            if cve in snaps:
                continue
            res = {name: c.check_cve(cve) for name, c in clients.items()}
            snaps[cve] = {'cve': cve, 'collected_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'api_results': res}
            SNAP.parent.mkdir(parents=True, exist_ok=True)
            SNAP.write_text(json.dumps(snaps, indent=1, ensure_ascii=False, default=str), encoding='utf-8')
            ok = [n for n, r in res.items() if 'error' not in r]
            print(f'[{i:3d}/{len(rows)}] {cve:18s} ok={len(ok)}/4 {[n for n in res if n not in ok]}', flush=True)
            time.sleep(NVD_PAUSE)


def evaluate():
    from app import create_app
    from app.services.llm_orchestrator import LLMOrchestrator
    from app.services.cve_attack_mapper import heuristic_techniques, _load
    app = create_app()
    rows = json.loads(DATASET.read_text(encoding='utf-8'))
    snaps = json.loads(SNAP.read_text(encoding='utf-8'))
    LEVELS = ['LIMPIO', 'BAJO', 'MEDIO', 'ALTO', 'CRÍTICO']
    out = []
    with app.app_context():
        o = LLMOrchestrator()
        for r in rows:
            s = snaps.get(r['cve'])
            if not s:
                continue
            res = s['api_results']
            los = {k: v for k, v in res.items() if k != 'cisa_kev'}
            out.append({**r, 'score': o._calculate_enhanced_score(res, {}), 'score_los': o._calculate_enhanced_score(los, {}),
                        'res': res})
        for r in out:
            r['level'] = o._determine_risk_level(r['score'])
            r['level_los'] = o._determine_risk_level(r['score_los'])
        ctid_idx = _load()

    def auc(rs, key):
        m = [r[key] for r in rs if r['label'] == 'kev']
        b = [r[key] for r in rs if r['label'] == 'no_kev']
        return sum(1 if x > y else .5 if x == y else 0 for x in m for y in b) / (len(m) * len(b)) if m and b else None

    lab = [r for r in out if r['group'] in ('kev', 'no_kev')]
    L = ['# Línea base de CVE (WP3)\n']
    L.append(f'CVEs con respuestas: **{len(out)}** ({sum(1 for r in lab if r["label"]=="kev")} KEV, '
             f'{sum(1 for r in lab if r["label"]=="no_kev")} sin KEV, {sum(1 for r in out if r["group"]=="ctid")} CTID).\n')
    L.append('Etiqueta = pertenencia a CISA KEV. **"Sin KEV" no es "no explotado"**: KEV es un catálogo incompleto.\n')
    L.append('### Nivel de riesgo (análisis completo)\n')
    L.append('| etiqueta | ' + ' | '.join(LEVELS) + ' |\n|---|' + '---|' * len(LEVELS))
    for lb in ('kev', 'no_kev'):
        sub = [r for r in lab if r['label'] == lb]
        L.append(f'| {lb} | ' + ' | '.join(str(sum(1 for r in sub if r['level'] == l)) for l in LEVELS) + ' |')
    L.append('\n### ¿Cuánto predicen la pertenencia a KEV las señales que NO son KEV? (AUC)\n')
    L.append(f'- Score completo (incluye KEV, tautológico): **{auc(lab, "score"):.2f}**')
    L.append(f'- Score SIN el cliente KEV (CVSS + EPSS + Exploit-DB): **{auc(lab, "score_los"):.2f}**')
    for name, fn in (('solo CVSS (NVD)', lambda r: r['res']['nvd'].get('cvss_score') or 0 if 'error' not in r['res']['nvd'] else 0),
                     ('solo EPSS', lambda r: r['res']['epss'].get('epss') or 0 if 'error' not in r['res']['epss'] else 0),
                     ('solo Exploit-DB', lambda r: r['res']['exploitdb'].get('exploit_count') or 0 if 'error' not in r['res']['exploitdb'] else 0)):
        tmp = [{**r, 'x': fn(r)} for r in lab]
        L.append(f'- {name}: {auc(tmp, "x"):.2f}')
    L.append('\n### Cobertura de las APIs\n')
    L.append('| API | ok | error |\n|---|---|---|')
    for api in ('nvd', 'cisa_kev', 'epss', 'exploitdb'):
        ok = sum(1 for r in out if 'error' not in r['res'][api])
        L.append(f'| {api} | {ok} | {len(out) - ok} |')

    ct = [r for r in out if r['group'] == 'ctid' and 'error' not in r['res']['nvd'] and r['res']['nvd'].get('found')]
    L.append(f'\n### Heurística MITRE (vector CVSS) frente al mapeo curado CTID — {len(ct)} CVEs\n')
    stats = {}
    # T1203 y T1068 se evaluaron y eliminaron (ver cve_attack_mapper.py); se siguen midiendo para ver si el vector las respalda
    from app.services.cve_attack_mapper import heuristic_techniques as _h
    probe = {'T1203': lambda n: ['T1203'] if str(n.get('attack_vector') or '').upper() in ('NETWORK', 'ADJACENT_NETWORK', 'ADJACENT') and str(n.get('user_interaction') or '').upper() in ('REQUIRED', 'ACTIVE', 'PASSIVE') else [],
             'T1068': lambda n: ['T1068'] if str(n.get('attack_vector') or '').upper() in ('LOCAL', 'PHYSICAL') and str(n.get('privileges_required') or '').upper() in ('LOW', 'HIGH') else []}
    for t in ('T1190', 'T1203', 'T1068'):
        heuristic_techniques = (lambda n, _t=t: _h(n)) if t == 'T1190' else (lambda n, _t=t: probe[_t](n))
        tp = fp = fn = 0
        for r in ct:
            truth = t in ctid_idx.get(r['cve'], [])
            pred = t in heuristic_techniques(r['res']['nvd'])
            tp += truth and pred
            fp += (not truth) and pred
            fn += truth and not pred
        stats[t] = (tp, fp, fn)
        prec = f'{100*tp/(tp+fp):.0f}%' if tp + fp else 'n/a'
        rec = f'{100*tp/(tp+fn):.0f}%' if tp + fn else 'n/a'
        L.append(f'- **{t}**: aciertos={tp}, falsos positivos={fp}, omitidos={fn}  → precisión {prec}, recall {rec}')
    (HERE / 'CVE_REPORT.md').write_text('\n'.join(L), encoding='utf-8')
    (HERE / 'cve_results.json').write_text(json.dumps([{k: v for k, v in r.items() if k != 'res'} for r in out], indent=1), encoding='utf-8')
    print('\n'.join(L))


{'build': build, 'collect': collect, 'evaluate': evaluate}[sys.argv[1]]()
