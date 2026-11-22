"""
Cadena criptográfica de la auditoría (WP1):

    flask audit status                       ¿hay clave?, extremo de la cadena, filas sin sellar
    flask audit verify [--anchor POS:HASH]   recalcula toda la cadena; sale con código 1 si está rota
    flask audit anchor                       imprime el extremo (POS:HASH): guárdalo FUERA del servidor
    flask audit seal-legacy                  sella las filas anteriores a la cadena (una sola vez)

Nunca imprime la clave (solo su huella `key_id`).
"""
import click
from flask.cli import AppGroup
from sqlalchemy import text

from app import db
from app.services import audit_chain

audit_cli = AppGroup('audit', help='Cadena criptográfica de la auditoría')


@audit_cli.command('status')
def status():
    key = audit_chain.get_key()
    if key:
        click.echo(f'clave AUDIT_CHAIN_KEY : sí (key_id {audit_chain.key_id(key)})')
    else:
        click.echo('clave AUDIT_CHAIN_KEY : NO: SHA-256 simple, solo detecta ediciones torpes (obligatoria en producción)')
    t = audit_chain.tail()
    click.echo(f"extremo de la cadena  : {str(t['pos']) + ':' + t['hash'] if t else 'vacía'}")
    sin = db.session.execute(text('SELECT count(*) FROM audit_events WHERE chain_pos IS NULL')).scalar()
    click.echo(f'filas sin sellar      : {sin}')


@audit_cli.command('verify')
@click.option('--anchor', default=None, help='Ancla publicada (POS:HASH): detecta que borraron las últimas filas.')
def verify(anchor):
    try:
        r = audit_chain.verify_chain(anchor)
    except ValueError as e:
        raise click.ClickException(str(e))
    click.echo(f"eslabones comprobados : {r['checked']}")
    if r['unverifiable']:
        click.echo(f"sin poder recalcular  : {r['unverifiable']} (sellados con otra clave: solo se comprobó su enlace)")
    if r['anchor']:
        click.echo(f"ancla                 : {r['anchor']}")
    if r['ok']:
        click.echo('RESULTADO: cadena ÍNTEGRA')
        return
    b = r['broken']
    click.echo(f"RESULTADO: CADENA ROTA - {b['reason']}" + (f" (eslabón {b['pos']}, id {b['id']})" if b.get('pos') else ''), err=True)
    raise SystemExit(1)


@audit_cli.command('anchor')
def anchor():
    t = audit_chain.tail()
    if not t:
        raise click.ClickException('la cadena está vacía')
    click.echo(f"{t['pos']}:{t['hash']}")


@audit_cli.command('seal-legacy')
def seal_legacy():
    n = audit_chain.seal_legacy()
    click.echo(f'{n} fila(s) anteriores a la cadena selladas (se puede afirmar que no cambiaron DESDE ahora, no antes)')
