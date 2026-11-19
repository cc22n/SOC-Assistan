"""
Clientes de inteligencia para CVEs (WP3 de PLAN-FUSION): NVD, CISA KEV, EPSS y Exploit-DB.

Convención de resultado (igual que el resto de clientes): `{'error': ...}` si la consulta falló, `{'found': False}`
si la fuente respondió y no conoce el CVE, y un dict con datos si lo conoce.

Regla heredada de la línea base y de WP9: un HTTP 200 cuya forma NO es la esperada es un ERROR visible ("la forma de
la API pudo cambiar"), nunca un "sin datos". Por eso cada cliente valida la estructura antes de dar `found: False`.

Formas verificadas EN VIVO el 2026-11-19 (fixtures reales en tests/fixtures/cve/). Diferencias con el código de
ThreatChain que servía de origen, que habría devuelto vacíos sin error:
  * Exploit-DB: `description` es una lista [id, título] y `type`/`platform` son dicts {name, display}/{platform}
    (no `.val`); y su endpoint JSON de búsqueda responde 403 al User-Agent normal de la app. Se usa en su lugar el
    dataset OFICIAL (files_exploits.csv en GitLab), indexado por CVE.
  * NVD: la métrica útil es la de tipo "Primary" (la lista puede empezar por una "Secondary" de la CNA) y existen
    métricas CVSS 4.0; `cisa*` ya viene en el propio registro.
"""
import csv
import io
import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from flask import current_app

from app.utils.http_client import http_get

logger = logging.getLogger(__name__)

SHAPE_ERROR = 'respuesta con forma inesperada (¿cambió la API?)'


class _CachedCatalog:
    """
    Catálogo grande descargado una vez y compartido por el proceso (KEV ≈ 1.8 MB, Exploit-DB ≈ 10 MB).
    TTL; un solo hilo refresca mientras los demás esperan (evita N descargas simultáneas); si el refresco falla se
    sigue sirviendo la copia anterior marcada como `stale` (mejor datos de hace un día que ningún dato).
    """

    def __init__(self, name: str, ttl_seconds: int, loader: Callable[[], Any]):
        self.name = name
        self.ttl = ttl_seconds
        self._loader = loader
        self._lock = threading.Lock()
        self._data: Any = None
        self._loaded_at: float = 0.0

    def get(self):
        """(datos, stale). Lanza la excepción del loader si no hay ni copia anterior."""
        now = time.time()
        if self._data is not None and now - self._loaded_at < self.ttl:
            return self._data, False
        with self._lock:
            now = time.time()
            if self._data is not None and now - self._loaded_at < self.ttl:      # otro hilo ya refrescó
                return self._data, False
            try:
                self._data = self._loader()
                self._loaded_at = time.time()
                return self._data, False
            except Exception as e:
                if self._data is not None:
                    logger.warning('%s: refresco falló (%s); se sirve la copia anterior', self.name, e)
                    return self._data, True
                raise

    def reset(self):
        """Solo para tests."""
        with self._lock:
            self._data, self._loaded_at = None, 0.0


# ============================================================================ NVD

class NVDClient:
    """NVD (NIST) API 2.0. Sin clave: 5 peticiones / 30 s; con NVD_API_KEY: 50 / 30 s."""

    def __init__(self):
        self.base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
        self.api_key = current_app.config.get('API_KEYS', {}).get('nvd')

    @staticmethod
    def _pick_cvss(metrics: Dict) -> Dict[str, Any]:
        """La métrica CVSS más reciente disponible, prefiriendo la 'Primary' (NVD) sobre la 'Secondary' (CNA)."""
        for key in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
            entries = metrics.get(key) or []
            if not entries:
                continue
            m = next((e for e in entries if e.get('type') == 'Primary'), entries[0])
            d = m.get('cvssData') or {}
            return {
                'cvss_version': d.get('version'),
                'cvss_score': d.get('baseScore'),
                'cvss_severity': d.get('baseSeverity') or m.get('baseSeverity'),     # v2 la trae fuera de cvssData
                'cvss_vector': d.get('vectorString'),
                'attack_vector': d.get('attackVector') or d.get('accessVector'),
                'user_interaction': d.get('userInteraction'),
                'privileges_required': d.get('privilegesRequired'),
            }
        return {'cvss_version': None, 'cvss_score': None, 'cvss_severity': None, 'cvss_vector': None,
                'attack_vector': None, 'user_interaction': None, 'privileges_required': None}

    def check_cve(self, cve_id: str) -> Dict:
        try:
            headers = {'apiKey': self.api_key} if self.api_key else {}
            r = http_get(self.base_url, params={'cveId': cve_id}, headers=headers, timeout=20)
            if r.status_code in (403, 429):
                return {'error': f'HTTP {r.status_code}: límite de NVD (sin API key: 5 peticiones/30 s)'}
            if r.status_code != 200:
                return {'error': f'HTTP {r.status_code}'}
            try:
                data = r.json()
            except ValueError:
                return {'error': SHAPE_ERROR}
            vulns = data.get('vulnerabilities') if isinstance(data, dict) else None
            if not isinstance(vulns, list):
                return {'error': SHAPE_ERROR}
            if not vulns:
                return {'found': False}
            cve = (vulns[0] or {}).get('cve')
            if not isinstance(cve, dict) or not cve.get('id'):
                return {'error': SHAPE_ERROR}

            desc = next((d.get('value') for d in cve.get('descriptions', []) if d.get('lang') == 'en'), '')
            cwes: List[str] = []
            for w in cve.get('weaknesses', []):
                for d in w.get('description', []):
                    v = d.get('value')
                    if v and v.startswith('CWE-') and v not in cwes:
                        cwes.append(v)
            exploit_refs = [ref.get('url') for ref in cve.get('references', []) if 'Exploit' in (ref.get('tags') or [])]
            out = {
                'found': True,
                'id': cve['id'],
                'vuln_status': cve.get('vulnStatus'),
                'rejected': str(cve.get('vulnStatus', '')).lower() == 'rejected',
                'description': (desc or '')[:1500],
                'published': cve.get('published'),
                'last_modified': cve.get('lastModified'),
                'cwes': cwes,
                'exploit_reference_count': len(exploit_refs),
                'exploit_references': exploit_refs[:5],
                'references_total': len(cve.get('references', [])),
                'cisa_exploit_add': cve.get('cisaExploitAdd'),
            }
            out.update(self._pick_cvss(cve.get('metrics') or {}))
            return out
        except Exception as e:
            logger.error(f'NVD error: {e}')
            return {'error': str(e)}


# ============================================================================ CISA KEV

def _load_kev() -> Dict[str, Any]:
    r = http_get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f'HTTP {r.status_code}')
    data = r.json()
    vulns = data.get('vulnerabilities') if isinstance(data, dict) else None
    if not isinstance(vulns, list) or (vulns and 'cveID' not in vulns[0]):
        raise ValueError(SHAPE_ERROR)
    return {'by_cve': {v['cveID'].upper(): v for v in vulns if isinstance(v, dict) and v.get('cveID')},
            'version': data.get('catalogVersion'), 'count': data.get('count', len(vulns))}


_KEV = _CachedCatalog('cisa_kev', 6 * 3600, _load_kev)


class CISAKEVClient:
    """Catálogo CISA de Vulnerabilidades Explotadas Conocidas: 'explotada de verdad', no solo 'teóricamente grave'."""

    def check_cve(self, cve_id: str) -> Dict:
        try:
            catalog, stale = _KEV.get()
        except ValueError:
            return {'error': SHAPE_ERROR}
        except Exception as e:
            logger.error(f'KEV error: {e}')
            return {'error': str(e)}
        meta = {'catalog_version': catalog['version'], 'catalog_count': catalog['count'], 'stale': stale}
        v = catalog['by_cve'].get(cve_id.upper())
        if not v:
            return {'found': False, 'in_kev': False, **meta}
        return {
            'found': True, 'in_kev': True,
            'vendor_project': v.get('vendorProject'), 'product': v.get('product'),
            'vulnerability_name': v.get('vulnerabilityName'),
            'short_description': (v.get('shortDescription') or '')[:600],
            'date_added': v.get('dateAdded'), 'due_date': v.get('dueDate'),
            'required_action': (v.get('requiredAction') or '')[:500],
            'known_ransomware': str(v.get('knownRansomwareCampaignUse', '')).lower() == 'known',
            'cwes': v.get('cwes') or [],
            **meta,
        }


# ============================================================================ EPSS

class EPSSClient:
    """EPSS (FIRST.org): probabilidad de que el CVE se explote en los próximos 30 días (0-1) y su percentil."""

    def __init__(self):
        self.base_url = 'https://api.first.org/data/v1/epss'

    def check_cve(self, cve_id: str) -> Dict:
        try:
            r = http_get(self.base_url, params={'cve': cve_id}, timeout=15)
            if r.status_code != 200:
                return {'error': f'HTTP {r.status_code}'}
            try:
                data = r.json()
            except ValueError:
                return {'error': SHAPE_ERROR}
            rows = data.get('data') if isinstance(data, dict) else None
            if not isinstance(rows, list):
                return {'error': SHAPE_ERROR}
            if not rows:
                return {'found': False}            # CVE aún sin puntuar (recién publicado) o inexistente
            row = rows[0]
            try:
                return {'found': True, 'epss': float(row['epss']), 'percentile': float(row['percentile']),
                        'date': row.get('date')}
            except (KeyError, TypeError, ValueError):
                return {'error': SHAPE_ERROR}
        except Exception as e:
            logger.error(f'EPSS error: {e}')
            return {'error': str(e)}


# ============================================================================ Exploit-DB

def _load_exploitdb() -> Dict[str, List[Dict]]:
    """Dataset oficial de Exploit-DB (GitLab), indexado por CVE. ≈ 10 MB, ~47 000 filas."""
    r = http_get('https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv', timeout=60)
    if r.status_code != 200:
        raise RuntimeError(f'HTTP {r.status_code}')
    reader = csv.DictReader(io.StringIO(r.content.decode('utf-8', errors='replace')))
    if not reader.fieldnames or not {'id', 'description', 'codes'} <= set(reader.fieldnames):
        raise ValueError(SHAPE_ERROR)
    index: Dict[str, List[Dict]] = {}
    for row in reader:
        for code in (row.get('codes') or '').split(';'):
            code = code.strip().upper()
            if code.startswith('CVE-'):
                index.setdefault(code, []).append({
                    'id': row.get('id'), 'title': row.get('description'),
                    'date_published': row.get('date_published'), 'type': row.get('type'),
                    'platform': row.get('platform'), 'verified': row.get('verified') == '1',
                })
    for items in index.values():
        items.sort(key=lambda x: x.get('date_published') or '', reverse=True)
    return index


_EXPLOITDB = _CachedCatalog('exploitdb', 24 * 3600, _load_exploitdb)


class ExploitDBClient:
    """Exploits públicos conocidos para un CVE, según el dataset oficial de Exploit-DB."""

    def check_cve(self, cve_id: str) -> Dict:
        try:
            index, stale = _EXPLOITDB.get()
        except ValueError:
            return {'error': SHAPE_ERROR}
        except Exception as e:
            logger.error(f'Exploit-DB error: {e}')
            return {'error': str(e)}
        items = index.get(cve_id.upper(), [])
        if not items:
            return {'found': False, 'exploit_count': 0, 'stale': stale}
        return {'found': True, 'exploit_count': len(items),
                'verified_count': sum(1 for i in items if i['verified']),
                'exploits': items[:10], 'stale': stale}
