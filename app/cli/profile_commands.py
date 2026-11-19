"""Comandos de perfiles de investigación:  flask profiles seed | list"""
import click
from flask.cli import AppGroup

from app.models.profile import InvestigationProfile
from app.services.profile_service import ensure_system_profiles

profiles_cli = AppGroup('profiles', help='Perfiles de investigación')


@profiles_cli.command('seed')
def seed():
    """Crea/actualiza los perfiles del sistema (idempotente)."""
    r = ensure_system_profiles()
    click.echo(f"Perfiles del sistema: {r['created']} creados, {r['updated']} actualizados.")


@profiles_cli.command('list')
def list_():
    """Lista todos los perfiles."""
    for p in InvestigationProfile.query.order_by(InvestigationProfile.is_system.desc(), InvestigationProfile.ioc_type,
                                                 InvestigationProfile.name):
        origen = 'sistema' if p.is_system else f'usuario {p.owner_id}'
        click.echo(f'{p.id:4d}  {p.ioc_type:7s} {origen:12s} {p.name}  [{", ".join(p.apis)}]')
