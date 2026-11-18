"""
Comandos de línea de comandos para cuentas bloqueadas.

Imprescindibles cuando el PROPIO administrador queda bloqueado (5 fallos en 15 min) y no puede entrar a la web
para usar el desbloqueo:

    flask accounts locked
    flask accounts unlock <usuario>

Quien tiene acceso a la shell del servidor ya puede tocar la BD directamente, así que no se añade ninguna
autenticación extra; el desbloqueo queda en la auditoría como `cli:<usuario del sistema>`.
"""
import getpass

import click
from flask.cli import AppGroup

from app.utils.login_throttle import LOCKOUT_THRESHOLD, locked_accounts, unlock_account

accounts_cli = AppGroup('accounts', help='Cuentas bloqueadas por intentos de login fallidos')


@accounts_cli.command('locked')
def locked():
    """Lista las cuentas bloqueadas ahora."""
    cuentas = locked_accounts()
    if not cuentas:
        click.echo('Ninguna cuenta bloqueada.')
        return
    click.echo(f'{"USUARIO":28s} {"RESTANTE":>9s} {"FALLOS":>7s}  {"ÚLTIMA IP":16s} ÚLTIMO FALLO')
    for c in cuentas:
        click.echo(f'{c["username"]:28s} {c["restante_min"]:>6d} min {c["fallos"]:>7d}  '
                   f'{str(c["ultima_ip"] or "-"):16s} {c["ultimo_fallo"] or "-"}')
    click.echo(f'\n{len(cuentas)} cuenta(s) con {LOCKOUT_THRESHOLD}+ fallos en la ventana.')


@accounts_cli.command('unlock')
@click.argument('username')
def unlock(username):
    """Desbloquea USERNAME y reinicia su contador de fallos."""
    try:
        r = unlock_account(username, by=f'cli:{getpass.getuser()}')
    except ValueError as e:
        raise click.ClickException(str(e))
    except RuntimeError as e:
        raise click.ClickException(str(e))
    click.echo(f'{"Desbloqueada" if r["was_locked"] else "No estaba bloqueada (contador reiniciado)"}: {r["username"]}')
