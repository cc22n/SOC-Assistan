"""
Feeds proactivos (WP6):

    flask feeds run [--source cisa_kev|nvd_recent] [--lookback-days N]   ejecuta ahora (para pruebas o cron externo)
    flask feeds daemon [--poll 300]                                        bucle del servicio `feeds` de docker-compose
    flask feeds status                                                     última ejecución de cada fuente
    flask feeds stack-list | stack-add --vendor V --product P | stack-remove ID
"""
from datetime import timedelta
import logging

import click
from flask.cli import AppGroup

from app import db
from app.models.feed import FeedItem, FeedRun, TechStackEntry
from app.services import feed_runner
from app.services.feed_matching import entry_is_valid
from app.utils.time_utils import utcnow

feeds_cli = AppGroup('feeds', help='Feeds proactivos de CVEs filtrados por tu stack')


@feeds_cli.command('run')
@click.option('--source', type=click.Choice(sorted(feed_runner.SOURCES)), default=None, help='Solo esa fuente (por defecto, todas).')
@click.option('--lookback-days', type=int, default=None, help='Mirar N días atrás en vez de desde la última ejecución.')
def run(source, lookback_days):
    """Ejecuta las fuentes AHORA, estén vencidas o no."""
    lookback = timedelta(days=lookback_days) if lookback_days else None
    for name in ([source] if source else list(feed_runner.SOURCES)):
        r = feed_runner.run_source(name, lookback=lookback)
        click.echo(f"{r['source']:12s} {r['status']:8s} traídos={r.get('fetched', 0)} nuevos={r.get('new', 0)} "
                   f"actualizados={r.get('updated', 0)} alertas={r.get('alerts', 0)} escalados={r.get('escalated', 0)}"
                   + (f"  ERROR: {r['error']}" if r.get('error') else ''))
    from app.services import feed_notifier
    avisos = feed_notifier.notify_pending()
    if avisos['status'] != 'disabled':
        click.echo(f"avisos Telegram: {avisos['status']} ({avisos.get('items', 0)} CVE)")


@feeds_cli.command('daemon')
@click.option('--poll', type=int, default=300, show_default=True, help='Segundos entre comprobaciones de qué está vencido.')
def daemon(poll):
    """Proceso de larga vida: ejecuta las fuentes cuando vencen (sobrevive a reinicios: lo vencido sale de feed_runs)."""
    logging.basicConfig(level=logging.INFO)
    feed_runner.daemon(poll_seconds=poll)


@feeds_cli.command('status')
def status():
    """Última ejecución de cada fuente y totales."""
    for name, spec in feed_runner.SOURCES.items():
        last = FeedRun.query.filter_by(source=name).order_by(FeedRun.started_at.desc()).first()
        ok = feed_runner.last_ok_run(name)
        click.echo(f"{name:12s} última={last.status if last else 'nunca':8s} última_ok={ok.started_at.isoformat() if ok else '-':26s}"
                   f" vencida={'sí' if feed_runner.is_due(name, utcnow()) else 'no'}  (cada {spec.interval})")
    click.echo(f"CVEs: {FeedItem.query.count()} total, {FeedItem.query.filter_by(is_relevant=True).count()} relevantes; "
               f"stack: {TechStackEntry.query.count()} entradas")


@feeds_cli.command('stack-list')
def stack_list():
    for e in TechStackEntry.query.order_by(TechStackEntry.id):
        click.echo(f'{e.id:4d}  {e.vendor or "*":24s} {e.product or "*":28s} {e.note}')


@feeds_cli.command('stack-add')
@click.option('--vendor', default=None)
@click.option('--product', default=None)
@click.option('--note', default='')
def stack_add(vendor, product, note):
    if not entry_is_valid(vendor, product):
        raise click.ClickException('indica un vendor o un producto con algún nombre significativo')
    db.session.add(TechStackEntry(vendor=vendor, product=product, note=note))
    db.session.commit()
    click.echo(f"añadida; relevancia recalculada: {feed_runner.recompute_relevance()}")


@feeds_cli.command('stack-remove')
@click.argument('entry_id', type=int)
def stack_remove(entry_id):
    e = db.session.get(TechStackEntry, entry_id)
    if not e:
        raise click.ClickException('no existe')
    db.session.delete(e)
    db.session.commit()
    click.echo(f"borrada; relevancia recalculada: {feed_runner.recompute_relevance()}")
