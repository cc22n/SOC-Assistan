"""
Fuentes de los feeds proactivos (WP6): CISA KEV y CVEs graves recién publicados en NVD.

Cada `fetch_*` devuelve una lista de dicts normalizados (mismas claves para todas las fuentes) o LANZA `FeedError`:
un fallo o una forma inesperada es un error visible (queda en `feed_runs`), nunca "cero novedades" (regla de WP9).

Formas verificadas EN VIVO el 2026-11-19 (fixtures reales en tests/fixtures/feeds/):
  * NVD, CVE recién publicado: `configurations` (CPE) VACÍO en los 204 CVE graves de 48 h (el enriquecimiento llega días
    después), pero el 100 % trae vendor/producto en `affected[].affectedData[]` de la CNA -> es de ahí de donde se casa.
  * NVD no tiene título: se usa el inicio de la descripción.
  * EPSS no puntúa a los CVE de menos de ~1 día (1 de 8 devueltos): `epss=None` significa "aún sin puntuar", no 0.
"""
import logging
import time
from datetime import date, datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

from flask import current_app

from app.services import cve_clients
from app.services.cve_clients import NVDClient
from app.services.feed_matching import tokens
from app.utils.http_client import http_get

logger = logging.getLogger(__name__)

NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
EPSS_URL = 'https://api.first.org/data/v1/epss'
NVD_PAGE = 2000
NVD_MAX_WINDOW_DAYS = 120            # límite de NVD para pubStartDate/pubEndDate
EPSS_CHUNK = 50                      # la URL crece con cada CVE; 50 caben de sobra


class FeedError(RuntimeError):
    """Fallo (o forma inesperada) al obtener una fuente. Se registra en feed_runs."""


def _item(cve_id: str, **kw) -> Dict[str, Any]:
    base = {'cve_id': cve_id.upper(), 'title': '', 'summary': '', 'published_at': None, 'source': '', 'affected': [],
            'in_kev': False, 'kev_date_added': None, 'known_ransomware': False, 'cvss_score': None, 'epss': None}
    base.update(kw)
    return base


# ============================================================================ CISA KEV

def fetch_kev(since: date) -> List[Dict[str, Any]]:
    """Entradas de KEV con `dateAdded >= since`. Descarga el catálogo completo (≈ 1.8 MB) sin pasar por la caché."""
    try:
        catalog = cve_clients._load_kev()
    except Exception as e:
        raise FeedError(f'KEV: {e}') from e
    out = []
    for cve, v in catalog['by_cve'].items():
        try:
            added = date.fromisoformat(v.get('dateAdded', ''))
        except ValueError:
            continue
        if added < since:
            continue
        out.append(_item(
            cve, source='cisa_kev', title=(v.get('vulnerabilityName') or '')[:300],
            summary=(v.get('shortDescription') or '')[:1000],
            published_at=datetime(added.year, added.month, added.day), in_kev=True, kev_date_added=added,
            known_ransomware=str(v.get('knownRansomwareCampaignUse', '')).lower() == 'known',
            affected=[{'vendor': v.get('vendorProject'), 'product': v.get('product')}]))
    return out


# ============================================================================ NVD

def _parse_nvd_item(cve: Dict[str, Any]) -> Dict[str, Any]:
    desc = next((d.get('value') for d in cve.get('descriptions', []) if d.get('lang') == 'en'), '') or ''
    affected: List[Dict[str, Optional[str]]] = []
    for a in cve.get('affected') or []:
        for d in a.get('affectedData') or []:
            pair = {'vendor': d.get('vendor'), 'product': d.get('product')}
            if (tokens(pair['vendor']) or tokens(pair['product'])) and pair not in affected:
                affected.append(pair)
    published = cve.get('published')
    return _item(
        cve['id'], source='nvd_recent', title=desc.strip().replace('\n', ' ')[:200], summary=desc[:1000],
        published_at=datetime.fromisoformat(published[:19]) if published else None,
        cvss_score=NVDClient._pick_cvss(cve.get('metrics') or {}).get('cvss_score'), affected=affected)


def fetch_nvd_recent(since: datetime, now: datetime, sleep: Callable[[float], None] = time.sleep) -> List[Dict[str, Any]]:
    """CVEs CRITICAL y HIGH (CVSS v3) publicados entre `since` y `now`. Sin API key hay que espaciar las peticiones (5/30 s)."""
    since = max(since, now - timedelta(days=NVD_MAX_WINDOW_DAYS))
    key = current_app.config.get('API_KEYS', {}).get('nvd')
    headers = {'apiKey': key} if key else {}
    pause = 1.0 if key else 7.0
    fmt = '%Y-%m-%dT%H:%M:%S.000'
    out: Dict[str, Dict[str, Any]] = {}
    first = True
    for severity in ('CRITICAL', 'HIGH'):
        start_index = 0
        while True:
            if not first:
                sleep(pause)
            first = False
            try:
                r = http_get(NVD_URL, headers=headers, timeout=90, params={
                    'pubStartDate': since.strftime(fmt), 'pubEndDate': now.strftime(fmt),
                    'cvssV3Severity': severity, 'resultsPerPage': NVD_PAGE, 'startIndex': start_index})
            except Exception as e:
                raise FeedError(f'NVD: {e}') from e
            if r.status_code in (403, 429):
                raise FeedError(f'NVD HTTP {r.status_code}: límite de peticiones')
            if r.status_code != 200:
                raise FeedError(f'NVD HTTP {r.status_code}')
            try:
                data = r.json()
            except ValueError as e:
                raise FeedError('NVD: respuesta no JSON') from e
            vulns = data.get('vulnerabilities') if isinstance(data, dict) else None
            if not isinstance(vulns, list) or not isinstance(data.get('totalResults'), int):
                raise FeedError(cve_clients.SHAPE_ERROR)
            for v in vulns:
                cve = (v or {}).get('cve')
                if not isinstance(cve, dict) or not cve.get('id'):
                    raise FeedError(cve_clients.SHAPE_ERROR)
                out[cve['id']] = _parse_nvd_item(cve)
            start_index += NVD_PAGE
            if start_index >= data['totalResults']:
                break
    return list(out.values())


# ============================================================================ EPSS (enriquecimiento)

def fetch_epss(cve_ids: List[str]) -> Dict[str, float]:
    """{cve: probabilidad}. Mejor esfuerzo: si falla se devuelve lo obtenido (EPSS enriquece, no decide qué hay de nuevo)."""
    result: Dict[str, float] = {}
    for i in range(0, len(cve_ids), EPSS_CHUNK):
        chunk = cve_ids[i:i + EPSS_CHUNK]
        try:
            r = http_get(EPSS_URL, params={'cve': ','.join(chunk)}, timeout=30)
            rows = r.json().get('data') if r.status_code == 200 else None
            if not isinstance(rows, list):
                logger.warning('EPSS: respuesta inesperada (HTTP %s)', r.status_code)
                continue
            for row in rows:
                try:
                    result[row['cve'].upper()] = float(row['epss'])
                except (KeyError, TypeError, ValueError):
                    continue
        except Exception as e:
            logger.warning('EPSS: %s', e)
    return result
