.PHONY: help install init run test clean

help:
	@echo "SOC Agent - Comandos disponibles:"
	@echo ""
	@echo "  make install    - Instalar dependencias"
	@echo "  make init       - Inicializar base de datos"
	@echo "  make run        - Ejecutar en modo desarrollo"
	@echo "  make test       - Ejecutar tests"
	@echo "  make clean      - Limpiar archivos temporales"
	@echo "  make reset-db   - Resetear base de datos (CUIDADO!)"
	@echo ""

install:
	@echo "📦 Instalando dependencias..."
	pip install -r requirements.txt
	@echo "✅ Dependencias instaladas"

init:
	@echo "🗄️  Inicializando base de datos..."
	python init_db.py
	@echo "✅ Base de datos inicializada"

run:
	@echo "🚀 Iniciando SOC Agent en modo desarrollo..."
	@echo "📍 http://localhost:5000"
	flask run --debug

test:
	@echo "🧪 Ejecutando tests..."
	pytest -v

clean:
	@echo "🧹 Limpiando archivos temporales..."
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.log" -delete
	@echo "✅ Limpieza completada"

reset-db:
	@echo "⚠️  Reseteando base de datos..."
	python init_db.py reset

prod:
	@echo "🚀 Iniciando en modo producción..."
	gunicorn -w 4 -b 0.0.0.0:5000 wsgi:app

setup: install init
	@echo "✅ Setup completo - ejecuta 'make run' para iniciar"