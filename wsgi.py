"""
WSGI entry point para producción
"""
import os
from app import create_app

# Obtener configuración del entorno
config_name = os.getenv('FLASK_ENV', 'production')

# Crear aplicación
app = create_app(config_name)

# Configurar ProxyFix para reverse proxy (1 nivel de proxy: Nginx/Traefik/ALB)
if not app.debug and not app.testing:
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=1,
        x_proto=1,
        x_host=1,
        x_prefix=1
    )

if __name__ == '__main__':
    app.run()

