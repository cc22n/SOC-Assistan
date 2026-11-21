"""
Telegram (WP7):

    flask telegram status     ¿configurado? chats (enmascarados), umbral y cuántos avisos hay pendientes
    flask telegram test       comprueba el token (getMe) y envía un mensaje de prueba a cada chat permitido

`test` es la verificación REAL: sin ella no se puede dar el WP por hecho (las pruebas con respuestas simuladas no bastan).
Pasos previos del usuario: crear un bot con @BotFather, poner TELEGRAM_BOT_TOKEN y TELEGRAM_ALERT_CHAT_IDS en .env/.env.docker.
Nunca imprime el token.
"""
import click
from flask.cli import AppGroup

from app.services import feed_notifier, telegram_client

telegram_cli = AppGroup('telegram', help='Avisos de los feeds por Telegram')


@telegram_cli.command('status')
def status():
    chats = [telegram_client.mask_chat(c) for c in telegram_client.alert_chats()]
    click.echo(f"token configurado : {'sí' if telegram_client._configured_token() else 'NO (TELEGRAM_BOT_TOKEN vacío)'}")
    click.echo(f"chats permitidos  : {', '.join(chats) if chats else 'ninguno (TELEGRAM_ALERT_CHAT_IDS vacío)'}")
    click.echo(f"avisos activos    : {'sí' if telegram_client.configured() else 'NO (hacen falta token y al menos un chat)'}")
    click.echo(f"umbral de riesgo  : {feed_notifier.min_risk()} o más")
    if telegram_client.configured():
        click.echo(f"pendientes de avisar ahora: {len(feed_notifier.pending_items())}")


@telegram_cli.command('test')
def test():
    """Comprueba el token y envía un mensaje de prueba a cada chat permitido."""
    if not telegram_client.configured():
        raise click.ClickException('Falta TELEGRAM_BOT_TOKEN o TELEGRAM_ALERT_CHAT_IDS (ver `flask telegram status`).')
    try:
        me = telegram_client.get_me()
    except telegram_client.TelegramError as e:
        raise click.ClickException(f'El token no sirve: {e}')
    click.echo(f"bot: @{me.get('username')} ({me.get('first_name')})")
    res = telegram_client.send_to_chats('<b>SOC Agent</b>: mensaje de prueba. Si lo lees, los avisos de los feeds llegarán aquí.')
    for chat in res['sent']:
        click.echo(f'  {telegram_client.mask_chat(chat)}: enviado')
    for chat, err in res['transient'] + res['permanent']:
        click.echo(f'  {telegram_client.mask_chat(chat)}: FALLÓ ({err})')
    if not res['sent']:
        raise click.ClickException('No se pudo enviar a ningún chat. ¿Has escrito antes al bot (/start) desde ese chat?')
