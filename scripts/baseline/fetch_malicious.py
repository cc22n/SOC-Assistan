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
UA = {'User-Agent': 'Mozilla/5.0'}


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


def independent():
    """Etiquetas que NO vienen de abuse.ch (las otras son circulares con ThreatFox/URLhaus/MalwareBazaar)."""
    out = {'ip_indep': [], 'url_indep': []}
    for name, url in (('cins_army', 'https://cinsscore.com/list/ci-badguys.txt'),
                      ('emerging_threats', 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt')):
        try:
            r = requests.get(url, headers=UA, timeout=40)
            r.raise_for_status()
            for line in r.text.split():
                if line.count('.') == 3 and all(p.isdigit() for p in line.split('.')):
                    out['ip_indep'].append({'value': line, 'source': name})
        except Exception as e:
            print(name, 'ERROR', type(e).__name__, str(e)[:100])
    try:
        r = requests.get('https://openphish.com/feed.txt', headers=UA, timeout=40, allow_redirects=True)
        r.raise_for_status()
        out['url_indep'] = [{'value': u.strip(), 'source': 'openphish'} for u in r.text.split('\n') if u.startswith('http')]
    except Exception as e:
        print('openphish ERROR', type(e).__name__, str(e)[:100])
    return out


def main():
    out = {'ip': [], 'domain': [], 'url': [], 'hash': []}
    out.update(independent())
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
