"""
Flask CLI Commands - MITRE ATT&CK Management
Sprint 5

Uso:
    flask mitre update    - Descarga y actualiza datos desde MITRE oficial
    flask mitre stats     - Muestra estadísticas del dataset
    flask mitre seed      - Carga datos hardcodeados como fallback inicial
"""
import click
from flask.cli import AppGroup

mitre_cli = AppGroup('mitre', help='MITRE ATT&CK management commands')


@mitre_cli.command('update')
def update_mitre():
    """Descarga datos actualizados de MITRE ATT&CK"""
    click.echo('Downloading MITRE ATT&CK STIX bundle...')
    click.echo('(This may take 30-60 seconds)')

    from app.services.mitre_service import get_mitre_service
    svc = get_mitre_service()
    result = svc.update_from_stix()

    if result.get('success'):
        click.echo(click.style('Update successful!', fg='green'))
        click.echo(f"  Techniques: {result['techniques']}")
        click.echo(f"  Malware mappings: {result['malware_mappings']}")
        click.echo(f"  STIX version: {result.get('version', 'unknown')}")
    else:
        click.echo(click.style(f"Update failed: {result.get('error')}", fg='red'))


@mitre_cli.command('stats')
def mitre_stats():
    """Muestra estadísticas del dataset MITRE"""
    from app.services.mitre_service import get_mitre_service
    svc = get_mitre_service()
    stats = svc.get_stats()

    click.echo('MITRE ATT&CK Dataset Stats:')
    click.echo(f"  Techniques in DB: {stats['techniques_in_db']}")
    click.echo(f"  Malware mappings: {stats['malware_in_db']}")
    click.echo(f"  Last update: {stats['last_update'] or 'Never'}")
    click.echo(f"  Source: {stats['source']}")
    click.echo(f"  Version: {stats.get('version') or 'N/A'}")
    click.echo(f"  Cache stale: {stats['cache_stale']}")

    if stats['techniques_in_db'] == 0:
        click.echo(click.style(
            '\nNo data loaded! Run: flask mitre update', fg='yellow'
        ))


@mitre_cli.command('seed')
def seed_mitre():
    """Carga datos hardcodeados como fallback inicial"""
    from app import db
    from app.models.mitre import MITRE_TECHNIQUES_DB, MALWARE_TO_TECHNIQUES
    from app.services.mitre_service import MITRETechnique, MITREMalwareMapping, MITREUpdateLog
    from datetime import datetime

    click.echo('Seeding MITRE data from hardcoded values...')

    count_t = 0
    for tid, info in MITRE_TECHNIQUES_DB.items():
        existing = MITRETechnique.query.filter_by(technique_id=tid).first()
        if existing:
            continue
        tech = MITRETechnique(
            technique_id=tid,
            name=info['name'],
            tactic=info['tactic'],
            tactics=[info['tactic']],
            is_subtechnique='.' in tid,
            parent_id=tid.split('.')[0] if '.' in tid else None,
            url=f'https://attack.mitre.org/techniques/{tid.replace(".", "/")}/',
            updated_at=datetime.utcnow()
        )
        db.session.add(tech)
        count_t += 1

    count_m = 0
    for malware, techniques in MALWARE_TO_TECHNIQUES.items():
        existing = MITREMalwareMapping.query.filter_by(malware_name=malware).first()
        if existing:
            continue
        mapping = MITREMalwareMapping(
            malware_name=malware,
            technique_ids=techniques,
            updated_at=datetime.utcnow()
        )
        db.session.add(mapping)
        count_m += 1

    log = MITREUpdateLog(
        source='hardcoded_fallback',
        techniques_count=count_t,
        malware_count=count_m,
        success=True,
        version='hardcoded'
    )
    db.session.add(log)
    db.session.commit()

    click.echo(click.style(f'Seeded {count_t} techniques, {count_m} malware mappings', fg='green'))
