"""
Paso 2 de la línea base: arma scripts/baseline/dataset.json (IOC + etiqueta + categoría + procedencia).

Etiquetas:
  malicious : reportado por abuse.ch (ThreatFox/URLhaus/MalwareBazaar) en los últimos días  (fetch_malicious.py)
  benign    : infraestructura/sitios/binarios de sistema notoriamente legítimos
  ambiguous : legítimo pero con "ruido" que suele disparar falsos positivos (nodos Tor, escáneres, pastebins)
              -> NO se puntúa como acierto/fallo; se reporta aparte.

Selección de maliciosos determinista (semilla fija) y priorizando confianza alta, para que se pueda repetir.
"""
import hashlib
import json
import os
import random
from pathlib import Path

HERE = Path(__file__).parent
cand = json.loads((HERE / 'malicious_candidates.json').read_text(encoding='utf-8'))
TAG = os.environ.get('BASELINE_TAG', '')      # '' = la línea base original (2026-11-18); '_2026-11-19' = el repaso
rnd = random.Random(int(''.join(c for c in (TAG or '20261118') if c.isdigit())))
N = 10


def pick(items, n, key=lambda x: 0):
    items = sorted(items, key=key, reverse=True)
    top = items[: max(n * 4, n)]
    rnd.shuffle(top)
    seen, out = set(), []
    for x in top:
        if x['value'] not in seen:
            seen.add(x['value'])
            out.append(x)
        if len(out) == n:
            break
    return out


def sha256_of(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


rows = []


def add(value, ioc_type, label, category, source, note=''):
    rows.append({'value': value, 'type': ioc_type, 'label': label, 'category': category,
                 'label_source': source, 'note': note})


for t in ('ip', 'domain'):
    for x in pick(cand[t], N, key=lambda x: x.get('confidence') or 0):
        add(x['value'], t, 'malicious', 'ioc_reciente', 'threatfox', f"malware={x.get('malware')} conf={x.get('confidence')}")
for x in pick(cand['url'], N):
    add(x['value'], 'url', 'malicious', 'ioc_reciente', 'urlhaus', f"threat={x.get('malware')}")
for x in pick(cand['hash'], N):
    add(x['value'], 'hash', 'malicious', 'ioc_reciente', 'malwarebazaar', f"sig={x.get('malware')}")

# ---- maliciosos con etiqueta INDEPENDIENTE de abuse.ch (solo si la fuente respondió; ver fetch_malicious.py)
for src in ('cins_army', 'emerging_threats'):
    pool = [x for x in cand.get('ip_indep', []) if x['source'] == src]
    for x in pick(pool, 5):
        add(x['value'], 'ip', 'malicious', 'ip_en_lista_negra', src, 'IP en lista negra pública (atacante, no necesariamente C2)')
for x in pick(cand.get('url_indep', []), N):
    add(x['value'], 'url', 'malicious', 'phishing_reciente', 'openphish', 'URL de phishing')

# ---- benignos
for ip, nota in [('8.8.8.8', 'Google DNS'), ('1.1.1.1', 'Cloudflare DNS'), ('9.9.9.9', 'Quad9 DNS'),
                 ('208.67.222.222', 'OpenDNS'), ('140.82.112.3', 'GitHub'), ('151.101.1.69', 'Fastly/Reddit CDN'),
                 ('13.107.42.14', 'Microsoft'), ('17.253.144.10', 'Apple')]:
    add(ip, 'ip', 'benign', 'infra_legitima', 'conocimiento_publico', nota)
for d in ['google.com', 'github.com', 'microsoft.com', 'wikipedia.org', 'python.org', 'mozilla.org',
          'debian.org', 'kernel.org', 'apache.org', 'cloudflare.com']:
    add(d, 'domain', 'benign', 'sitio_legitimo', 'conocimiento_publico')
for u in ['https://www.google.com/', 'https://github.com/', 'https://www.python.org/downloads/',
          'https://en.wikipedia.org/wiki/Malware', 'https://www.mozilla.org/en-US/firefox/',
          'https://docs.python.org/3/', 'https://www.debian.org/', 'https://kernel.org/']:
    add(u, 'url', 'benign', 'sitio_legitimo', 'conocimiento_publico')
add('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'hash', 'benign', 'archivo_vacio',
    'conocimiento_publico', 'SHA-256 del archivo vacío (lo conoce todo el mundo)')
for f in ['notepad.exe', 'calc.exe', 'cmd.exe', 'ping.exe', 'tasklist.exe', 'whoami.exe', 'hostname.exe']:
    p = Path(r'C:\Windows\System32') / f
    if p.exists():
        add(sha256_of(p), 'hash', 'benign', 'binario_sistema', 'windows_local', f'{f} de este equipo')

# ---- ambiguos
tor = Path(HERE / 'tor_exits.txt')
if tor.exists():
    for ip in tor.read_text().split()[:5]:
        add(ip, 'ip', 'ambiguous', 'nodo_tor', 'check.torproject.org', 'nodo de salida Tor: anonimizador, no malware')
for ip, nota in [('71.6.135.131', 'escáner Shodan'), ('162.142.125.10', 'escáner Censys'), ('198.20.69.74', 'escáner Shodan')]:
    add(ip, 'ip', 'ambiguous', 'escaner_internet', 'conocimiento_publico', nota)
for d in ['pastebin.com', 'ngrok.io', 'duckdns.org']:
    add(d, 'domain', 'ambiguous', 'servicio_doble_uso', 'conocimiento_publico', 'abusado a menudo, legítimo en sí')

out = HERE / f'dataset{TAG}.json'
out.write_text(json.dumps(rows, indent=1, ensure_ascii=False), encoding='utf-8')
from collections import Counter
print(len(rows), 'IOCs ->', out.name)
print(dict(Counter((r['label'], r['type']) for r in rows)))
