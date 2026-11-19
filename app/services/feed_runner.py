"""
Ejecución de los feeds proactivos (WP6): trae lo nuevo de cada fuente, lo funde por CVE, puntúa y casa con el stack.

Por qué NO Celery ni APScheduler dentro de la app (verificado en el código el 2026-11-19: SOC Agent no tenía planificador y
Gunicorn arranca 3 workers):
  * Un planificador dentro del proceso web se ejecutaría 3 veces (una por worker).
  * Celery exige broker + worker + beat (3 procesos más) para dos tareas cada 6 horas.
Basta un proceso aparte (`flask feeds daemon`, servicio `feeds` de docker-compose) que cada pocos minutos mira qué fuentes
están VENCIDAS según `feed_runs` (así sobrevive a un reinicio) y las ejecuta. Un `pg_advisory_lock` por fuente impide que dos
instancias (daemon + `flask feeds run` a mano) ejecuten la misma fuente a la vez.

Todas las operaciones son idempotentes: re-ejecutar una fuente no duplica nada (UNIQUE cve_id).
"""
import logging
import time
import zlib
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy import text

from app import db
from app.models.feed import FeedItem, FeedRun, TechStackEntry
from app.services import feed_sources
from app.services.feed_matching import match_entries
from app.utils.time_utils import utcnow

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SourceSpec:
    name: str
    interval: timedelta              # cada cuánto se considera vencida
    first_lookback: timedelta        # hasta dónde mirar atrás en la PRIMERA ejecución (si no, se inundaría de histórico)
    overlap: timedelta               # solapamiento con la ejecución anterior (el upsert es idempotente)


SOURCES: Dict[str, SourceSpec] = {
    'cisa_kev': SourceSpec('cisa_kev', timedelta(hours=6), timedelta(days=30), timedelta(days=1)),
    'nvd_recent': SourceSpec('nvd_recent', timedelta(hours=6), timedelta(days=3), timedelta(hours=2)),
}


def _fetch(name: str, since: datetime, now: datetime, fetchers: Optional[Dict[str, Callable]] = None) -> List[Dict[str, Any]]:
    if fetchers and name in fetchers:
        return fetchers[name](since, now)
    if name == 'cisa_kev':
        return feed_sources.fetch_kev(since.date())
    if name == 'nvd_recent':
        return feed_sources.fetch_nvd_recent(since, now)
    raise ValueError(f'fuente desconocida: {name}')


def _score(item: FeedItem) -> int:
    """Misma lógica de puntos que el análisis de un CVE (`LLMOrchestrator._cve_points`): una sola definición de 'peligroso'."""
    from app.services.llm_orchestrator import LLMOrchestrator
    pts = LLMOrchestrator._cve_points('cisa_kev', {'in_kev': item.in_kev, 'known_ransomware': item.known_ransomware})
    pts += LLMOrchestrator._cve_points('nvd', {'found': item.cvss_score is not None, 'cvss_score': item.cvss_score})
    pts += LLMOrchestrator._cve_points('epss', {'epss': item.epss})
    if item.in_kev:
        # SUELO: explotado en la naturaleza = ALTO como mínimo. KEV no trae CVSS y EPSS llega con retraso, así que un CVE
        # de KEV recién añadido sumaba solo los 40 de KEV (MEDIO): visto en la primera ejecución real (Cisco BroadWorks).
        pts = max(pts, 50)
    return min(100, pts)


def _level(score: int) -> str:
    from app.services.llm_orchestrator import LLMOrchestrator
    return LLMOrchestrator.__new__(LLMOrchestrator)._determine_risk_level(score)


def _merge_affected(old: List[Dict], new: List[Dict]) -> List[Dict]:
    out = list(old or [])
    for p in new or []:
        if p not in out:
            out.append(p)
    return out


def upsert_item(data: Dict[str, Any], entries: List[TechStackEntry], now: datetime) -> Dict[str, bool]:
    """
    Funde un CVE normalizado en la BD. Devuelve {'created', 'escalated', 'alert'}:
      created   el CVE no existía
      escalated ya existía y ahora entra en KEV (la información más importante que puede llegar)
      alert     casa con el stack Y es novedad (nuevo, escalado, o antes no casaba): lo que merece atención
    """
    item = FeedItem.query.filter_by(cve_id=data['cve_id']).first()
    created = item is None
    was_relevant = False if created else item.is_relevant
    if created:
        item = FeedItem(cve_id=data['cve_id'], first_seen_at=now, sources=[], affected=[], matched_entries=[])
        db.session.add(item)
    escalated = False

    sources = list(item.sources or [])
    if data['source'] not in sources:
        sources.append(data['source'])
    item.sources = sources
    if data.get('in_kev') and not item.in_kev:
        item.in_kev, item.kev_date_added = True, data.get('kev_date_added')
        if not created:
            escalated, item.escalated_at = True, now
    if data.get('known_ransomware'):
        item.known_ransomware = True
    if data.get('cvss_score') is not None:
        item.cvss_score = data['cvss_score']
    if data.get('epss') is not None:
        item.epss = data['epss']
    if not item.title and data.get('title'):
        item.title = data['title']
    if not item.summary and data.get('summary'):
        item.summary = data['summary']
    if data.get('published_at') and (item.published_at is None or data['published_at'] < item.published_at):
        item.published_at = data['published_at']
    item.affected = _merge_affected(item.affected, data.get('affected'))

    item.priority_score = _score(item)
    item.risk_level = _level(item.priority_score)
    item.matched_entries = match_entries(entries, item.affected)
    item.is_relevant = bool(item.matched_entries)
    return {'created': created, 'escalated': escalated,
            'alert': item.is_relevant and (created or escalated or not was_relevant)}


def recompute_relevance() -> Dict[str, int]:
    """Recalcula el casado de TODOS los CVE contra el stack actual (tras añadir o quitar una entrada)."""
    entries = TechStackEntry.query.all()
    changed = relevant = 0
    for item in FeedItem.query.yield_per(500):
        matched = match_entries(entries, item.affected)
        if matched != list(item.matched_entries or []) or item.is_relevant != bool(matched):
            item.matched_entries, item.is_relevant = matched, bool(matched)
            changed += 1
        relevant += bool(matched)
    db.session.commit()
    return {'changed': changed, 'relevant': relevant}


def _lock_key(name: str) -> int:
    return zlib.crc32(f'soc-agent-feed:{name}'.encode())


def last_ok_run(name: str) -> Optional[FeedRun]:
    return (FeedRun.query.filter_by(source=name, status='ok').order_by(FeedRun.started_at.desc()).first())


def run_source(name: str, now: Optional[datetime] = None, lookback: Optional[timedelta] = None,
               fetchers: Optional[Dict[str, Callable]] = None, enrich_epss: bool = True) -> Dict[str, Any]:
    """
    Ejecuta UNA fuente. Devuelve un resumen {'source','status','fetched','new','updated','alerts','escalated','error'}.
    `status` = 'skipped' si otra instancia ya la está ejecutando (advisory lock), 'error' si falló, 'ok' si no.
    """
    spec = SOURCES[name]
    now = now or utcnow()
    lock_conn = db.engine.connect()                  # conexión DEDICADA: el lock de sesión vive y muere con ella
    try:
        if not lock_conn.execute(text('SELECT pg_try_advisory_lock(:k)'), {'k': _lock_key(name)}).scalar():
            return {'source': name, 'status': 'skipped', 'error': 'otra instancia la está ejecutando'}
        try:
            return _run_locked(spec, now, lookback, fetchers, enrich_epss)
        finally:
            lock_conn.execute(text('SELECT pg_advisory_unlock(:k)'), {'k': _lock_key(name)})
    finally:
        lock_conn.close()


def _run_locked(spec: SourceSpec, now: datetime, lookback: Optional[timedelta],
                fetchers: Optional[Dict[str, Callable]], enrich_epss: bool) -> Dict[str, Any]:
    prev = last_ok_run(spec.name)
    if lookback is not None:
        since = now - lookback
    elif prev:
        since = prev.started_at - spec.overlap
    else:
        since = now - spec.first_lookback

    run = FeedRun(source=spec.name, started_at=now, status='running')
    db.session.add(run)
    db.session.commit()
    summary = {'source': spec.name, 'status': 'ok', 'fetched': 0, 'new': 0, 'updated': 0, 'alerts': 0,
               'escalated': 0, 'error': None}
    try:
        items = _fetch(spec.name, since, now, fetchers)
        run.fetched = summary['fetched'] = len(items)
        if enrich_epss and items:
            known = {i['cve_id'] for i in items if i.get('epss') is None}
            scores = feed_sources.fetch_epss(sorted(known)) if known else {}
            for i in items:
                if i['cve_id'] in scores:
                    i['epss'] = scores[i['cve_id']]
        entries = TechStackEntry.query.all()
        for data in items:
            r = upsert_item(data, entries, now)
            if r['created']:
                summary['new'] += 1
            else:
                summary['updated'] += 1
            summary['alerts'] += r['alert']
            summary['escalated'] += r['escalated']
        run.new_items, run.updated_items, run.relevant_new = summary['new'], summary['updated'], summary['alerts']
        run.status, run.finished_at = 'ok', utcnow()
        db.session.commit()
    except Exception as e:                           # una fuente que falla no debe tumbar a las demás ni dejar la BD a medias
        db.session.rollback()
        logger.error('feed %s falló: %s', spec.name, e, exc_info=not isinstance(e, feed_sources.FeedError))
        run = db.session.get(FeedRun, run.id)
        run.status, run.finished_at, run.error = 'error', utcnow(), str(e)[:500]
        db.session.commit()
        summary['status'], summary['error'] = 'error', str(e)[:500]
    return summary


def is_due(name: str, now: datetime) -> bool:
    prev = last_ok_run(name)
    return prev is None or now - prev.started_at >= SOURCES[name].interval


def run_due(now: Optional[datetime] = None, fetchers: Optional[Dict[str, Callable]] = None,
            enrich_epss: bool = True) -> List[Dict[str, Any]]:
    """Ejecuta las fuentes vencidas. Un fallo en una no impide ejecutar las demás."""
    now = now or utcnow()
    return [run_source(n, now=now, fetchers=fetchers, enrich_epss=enrich_epss) for n in SOURCES if is_due(n, now)]


def daemon(poll_seconds: int = 300, stop: Callable[[], bool] = lambda: False,
           sleep: Callable[[float], None] = time.sleep) -> None:
    """Bucle del servicio `feeds`: cada `poll_seconds` ejecuta lo vencido. `stop` y `sleep` son inyectables (tests)."""
    logger.info('feeds daemon iniciado (poll=%ss, fuentes=%s)', poll_seconds, list(SOURCES))
    while not stop():
        try:
            for r in run_due():
                logger.info('feeds: %s', r)
        except Exception as e:                       # nunca morir: el siguiente ciclo lo reintenta
            logger.error('feeds daemon: ciclo falló: %s', e, exc_info=True)
            db.session.rollback()
        sleep(poll_seconds)
