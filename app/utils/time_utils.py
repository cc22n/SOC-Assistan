import os
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

# Misma zona por defecto que app.config.Config.DISPLAY_TIMEZONE. Se lee de
# variable de entorno aquí también (en vez de current_app.config) porque este
# módulo lo usan modelos/servicios que no siempre corren dentro de un app context.
DISPLAY_TIMEZONE = os.environ.get('DISPLAY_TIMEZONE', 'America/Mexico_City')


def utcnow() -> datetime:
    """UTC actual como datetime naive (compatible con columnas TIMESTAMP naive)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def localnow() -> datetime:
    """Hora actual con tzinfo en DISPLAY_TIMEZONE (México por defecto).

    Usar para texto generado para el usuario (p. ej. títulos de sesión) donde
    mostrar UTC crudo confundiría al analista. Para timestamps de columnas de
    BD seguir usando utcnow().
    """
    return datetime.now(timezone.utc).astimezone(ZoneInfo(DISPLAY_TIMEZONE))
