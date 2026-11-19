"""
Paso 1 de la línea base (fase 0.2 de PLAN-FUSION): obtiene IOCs MALICIOSOS RECIENTES con veredicto conocido.

Los feeds públicos de abuse.ch devuelven 410; se usan sus APIs con ABUSECH_AUTH_KEY (la misma que ya usa la
app). Escribe scripts/baseline/malicious_candidates.json. NO imprime la clave.

Limitación declarada: la etiqueta "malicioso" proviene de abuse.ch, y el análisis consulta URLhaus/ThreatFox/
MalwareBazaar (también abuse.ch). Es circular para esas APIs; evaluate.py reporta también las métricas
EXCLUYENDO las APIs de la fuente de la etiqueta ('leave-source-out').

Uso:  python scripts/baseline/fetch_malicious.py
"""
import json
import os
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / '.env')
KEY = os.environ.get('ABUSECH_AUTH_KEY')
if not KEY:
    sys.exit('falta ABUSECH_AUTH_KEY en .env')
H = {'Auth-Key': KEY}
OUT = Path(__file__).with_name('malicious_candidates.json')


def threatfox(days=3):
    r = requests.post('https://threatfox-api.abuse.ch/api/v1/', headers=H, timeout=40,
                      json={'query': 'get_iocs', 'days': days})
    r.raise_for_status()
    j = r.json()
    return j.get('data') or []


def urlhaus_recent():
    r = requests.get('https://urlhaus-api.abuse.ch/v1/urls/recent/limit/50/', headers=H, timeout=40)
    r.raise_for_status()
    return r.json().get('urls') or []


def bazaar_recent():
    r = requests.post('https://mb-api.abuse.ch/api/v1/', headers=H, timeout=40,
                      data={'query': 'get_recent', 'selector': '100'})
    r.raise_for_status()
    return r.json().get('data') or []


def main():
    out = {'ip': [], 'domain': [], 'url': [], 'hash': []}
    try:
        for x in threatfox():
            t, v = x.get('ioc_type'), x.get('ioc')
            if t == 'ip:port' and v:
                out['ip'].append({'value': v.split(':')[0], 'malware': x.get('malware_printable'),
                                  'confidence': x.get('confidence_level'), 'source': 'threatfox'})
            elif t == 'domain' and v:
                out['domain'].append({'value': v, 'malware': x.get('malware_printable'),
                                      'confidence': x.get('confidence_level'), 'source': 'threatfox'})
    except Exception as e:
        print('threatfox ERROR', type(e).__name__, str(e)[:120])
    try:
        for x in urlhaus_recent():
            if x.get('url_status') == 'online':
                out['url'].append({'value': x['url'], 'malware': x.get('threat'), 'source': 'urlhaus'})
    except Exception as e:
        print('urlhaus ERROR', type(e).__name__, str(e)[:120])
    try:
        for x in bazaar_recent():
            if x.get('sha256_hash'):
                out['hash'].append({'value': x['sha256_hash'], 'malware': x.get('signature'),
                                    'source': 'malwarebazaar'})
    except Exception as e:
        print('bazaar ERROR', type(e).__name__, str(e)[:120])
    OUT.write_text(json.dumps(out, indent=1), encoding='utf-8')
    print({k: len(v) for k, v in out.items()}, '->', OUT.name)


main()
