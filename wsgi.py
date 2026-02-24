"""
WSGI entry point para producción
"""
import os
from app import create_app

# Obtener configuración del entorno
config_name = os.getenv('FLASK_ENV', 'production')

# Crear aplicación
app = create_app(config_name)

if __name__ == '__main__':
    app.run()

