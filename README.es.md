<div align="center">

# SOC Agent

### Plataforma de Threat Intelligence con IA para Analistas SOC

[![CI](https://github.com/cc22n/SOC-Assistan/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/cc22n/SOC-Assistan/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-green?logo=flask&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-blue?logo=postgresql&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow)
![APIs](https://img.shields.io/badge/APIs_Threat_Intel-19-red)
![LLMs](https://img.shields.io/badge/Proveedores_LLM-5-purple)
![Tests](https://img.shields.io/badge/Tests-375_pasando-brightgreen)

*Analiza IOCs, genera reportes profesionales y gestiona incidentes de seguridad desde una sola interfaz.*

[English Version / Versión en Inglés](README.md)

</div>

---

## ¿Qué es SOC Agent?

SOC Agent es una plataforma web de threat intelligence diseñada para analistas de Centros de Operaciones de Seguridad (SOC). Integra **20 APIs de threat intelligence**, **búsqueda OSINT web (Tavily)** y **5 proveedores de LLM** para analizar Indicadores de Compromiso (IOCs) como IPs, dominios, hashes y URLs.

El sistema permite a los analistas:
- Analizar IOCs contra múltiples fuentes simultáneamente
- Obtener análisis inteligente con IA y routing automático de LLMs
- Chatear con un asistente SOC que recuerda investigaciones pasadas y correlaciona amenazas
- Ejecutar análisis profundo con un agente de búsqueda web de 2 pasos (queries planificadas por LLM + síntesis con citas)
- Gestionar incidentes con tablero Kanban y vista de timeline
- Poner en whitelist falsos positivos conocidos para que salten el análisis
- Generar reportes profesionales en formato PDF y DOCX
- Correlacionar IOCs con técnicas MITRE ATT&CK
- Monitorear salud de APIs, circuit breakers y métricas de rendimiento en tiempo real

---

## Capturas de pantalla

**Chat IA analizando un IOC** — 18 APIs de threat intel + síntesis LLM, con memoria entre sesiones (el badge "Visto antes" enlaza a la investigación previa):

![Chat Analyst analizando un IOC](docs/screenshots/chat-analysis.png)

**Dashboard** — distribución de riesgo, timeline de análisis y top amenazas:

![Dashboard](docs/screenshots/dashboard.png)

**Historial de análisis** — filtrable, exportable, por analista:

![Historial de análisis](docs/screenshots/history.png)

---

## Arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│                         Frontend                             │
│  Dashboard │ Análisis │ Chat │ Incidentes │ Reportes │ Salud │
│              (Jinja2 + Tailwind + Chart.js)                  │
├─────────────────────────────────────────────────────────────┤
│                      Backend Flask                            │
│  ┌──────────┐  ┌──────────┐  ┌────────────────────────┐    │
│  │ Auth     │  │ API v2   │  │ Middleware de Seguridad │    │
│  │ (RBAC,   │  │ Routes   │  │ (Anti-SQLi, XSS,       │    │
│  │ Audit)   │  │          │  │  Prompt Injection)     │    │
│  └──────────┘  └──────────┘  └────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                 Capa de Servicios                    │    │
│  │  LLM Orchestrator (routing smart)  │ Session Manager │    │
│  │  Threat Intel + Circuit Breakers   │ Report Generator│    │
│  │  Caché IOC (TTL por tipo y riesgo) │ Metrics Engine  │    │
│  └─────────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌────────────────────────────────────┐   │
│  │ PostgreSQL   │  │ 20 APIs de Threat Intel            │   │
│  │ (Usuarios,   │  │ VirusTotal, AbuseIPDB, Shodan,     │   │
│  │  IOCs,       │  │ GreyNoise, OTX, ThreatFox,         │   │
│  │  Análisis,   │  │ URLhaus, MalwareBazaar,             │   │
│  │  Incidentes, │  │ SecurityTrails, Pulsedive, ...      │   │
│  │  Audit Log,  │  └────────────────────────────────────┘   │
│  │  Sesiones)   │  ┌────────────────────────────────────┐   │
│  └──────────────┘  │ 5 Proveedores LLM                  │   │
│                    │ xAI · OpenAI · Groq · Gemini        │   │
│                    │ Anthropic (Claude)                  │   │
│                    └────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## APIs Integradas

### Threat Intelligence (19)

| Categoría | APIs |
|-----------|------|
| **Reputación** | VirusTotal, AbuseIPDB, GreyNoise, Pulsedive |
| **Infraestructura** | Shodan, Shodan InternetDB, Criminal IP, SecurityTrails, Censys |
| **Malware** | ThreatFox, MalwareBazaar, Hybrid Analysis |
| **URLs** | URLhaus, URLScan, Google Safe Browsing |
| **Inteligencia** | AlienVault OTX |
| **Geolocalización** | IP-API (sin key), IPinfo, IPGeolocation.io |
| **Transparencia de certificados** | crt.sh (sin key) |
| **OSINT Web** | Tavily Search (búsqueda web para LLMs, usada por Deep Analysis) |

### Proveedores LLM (5)

| Proveedor | Modelo | Mejor para |
|-----------|--------|------------|
| **xAI** | Grok-3-mini | Análisis rápido, default |
| **OpenAI** | GPT-4o-mini | Análisis profundo, hashes |
| **Groq** | LLaMA 3.3 70B | Velocidad, tier gratuito |
| **Gemini** | Gemini 2.5 Flash | Contexto largo, tier gratuito |
| **Anthropic** | Claude Sonnet 4.6 | Razonamiento avanzado |

El orchestrator enruta automáticamente cada análisis al proveedor óptimo según el tipo de IOC y la profundidad (ej. Groq para IPs, OpenAI/Anthropic para hashes de malware).

---

## Funcionalidades

### Análisis de IOCs
- Análisis simultáneo contra múltiples APIs
- Detección automática del tipo de IOC (IP, dominio, hash, URL)
- Score de confianza y nivel de riesgo (CRÍTICO, ALTO, MEDIO, BAJO, LIMPIO)
- Mapeo automático a técnicas MITRE ATT&CK
- Routing inteligente de LLM: proveedor elegido según tipo de IOC y profundidad
- Validación Pydantic de todas las respuestas de APIs (detecta cambios de esquema)
- Whitelist de IOCs: los falsos positivos conocidos saltan el análisis (gestionada por API, auditada)

### Chat SOC con IA
- Asistente de investigación con contexto persistente
- Sesiones de investigación con historial completo y resúmenes auto-comprimidos
- **Memoria entre sesiones**: avisa cuando un IOC ya fue investigado antes (cuándo, riesgo, en qué investigación)
- **Grafo de correlación de amenazas**: señala IOCs previos que comparten familia de malware, técnicas MITRE, ASN o incidente ("posible misma campaña") — SQL puro, sin costo de LLM
- Re-consulta inteligente: si una pregunta necesita datos que faltan, solo se llaman las APIs faltantes y los resultados se persisten
- Export de sesión (JSON, Markdown, PDF, DOCX)
- Selector de proveedor LLM (xAI, OpenAI, Groq, Gemini, Claude)

### Deep Analysis + Agente OSINT Web
- Pipeline completo: 20 APIs + búsqueda web + correlación de IOCs + atribución APT + hipótesis de ataque
- **Agente de búsqueda de 2 pasos**: un LLM planifica queries dirigidas a partir de los hallazgos de las APIs (familia de malware, ASN — no el IOC crudo), Tavily busca con contenido extraído restringido a dominios de seguridad confiables, y un segundo LLM sintetiza los hallazgos **con citas obligatorias**
- Reintento amplio cuando las queries dirigidas no encuentran nada; fallback estático si no hay LLM disponible
- El contenido web se trata como no confiable (guard anti prompt-injection); no se afirma nada sin fuente
- Resultados de búsqueda web cacheados en PostgreSQL con TTL de 24h (ahorra créditos Tavily y llamadas LLM)

### Gestión de Incidentes
- Vista de tablero Kanban (Abierto, Investigando, Resuelto, Cerrado)
- Timeline integrado con mensajes del chat
- Múltiples IOCs vinculados por incidente (tabla pivote)
- Ticket IDs auto-generados (SOC-YYYYMMDD-NNN)
- Creación rápida desde análisis o chat
- API paginada con verificación de propiedad (protección IDOR)

### Dashboard
- Estadísticas en tiempo real con gráficas
- Distribución de riesgo, tendencias temporales
- IOCs recientes e incidentes abiertos
- Top de IOCs analizados

### Dashboard de Salud de APIs (`/api-health`)
- Vista unificada de cuotas de APIs (usadas / restantes hoy) y estados de circuit breakers
- Circuit breakers por API: CLOSED / OPEN / HALF-OPEN con conteo de fallos y timer de reintento
- Top 5 de APIs más lentas por latencia P95 con barras visuales
- Tabla de latencias de endpoints HTTP (P50 / P95 / P99 / promedio / tasa de error)
- Auto-refresh cada 30 segundos

### Reportes
- Generación de PDF profesional con ReportLab
- Generación de DOCX editable con python-docx
- Resumen ejecutivo, IOCs, MITRE ATT&CK, recomendaciones
- Datos crudos de APIs por IOC opcionales (`?include_api_details=true`) en PDF y DOCX

### Seguridad
- Autenticación con Flask-Login + hashing de contraseñas (Werkzeug)
- RBAC con 4 roles: `viewer`, `analyst`, `senior_analyst`, `admin`
- Creación de usuarios solo por admin (el primer usuario arranca como admin; rol asignado al crear)
- Protección CSRF en todos los formularios
- Rate limiting por IP y endpoint
- Middleware anti-inyección (SQLi, XSS, Command Injection, Path Traversal)
- **Protección contra prompt injection** — 15 patrones bloqueados antes de llegar al LLM
- Headers de seguridad (CSP, X-Frame-Options, HSTS, etc.)
- Endurecimiento de sesión (HttpOnly, SameSite, timeout)
- **Audit log append-only** — cada login, análisis y denegación de acceso queda registrado
- Límite de tamaño de request (16 MB) con handler 413

### Observabilidad
- **Logging JSON estructurado** con correlation ID por request
- **Métricas de ventana deslizante en memoria** (P50/P95/P99) sin dependencias externas
- Patrón circuit breaker para todas las APIs externas (CLOSED → OPEN → HALF-OPEN)
- Caché TTL diferenciado por tipo de IOC (IP: 1h, URL: 1h, dominio: 6h, hash: 24h)
- Índices compuestos de PostgreSQL para queries de alta cardinalidad
- Especificación OpenAPI completa en `/api/v2/openapi.json`

---

## Instalación

### Inicio rápido (Docker)

La forma más rápida de probar SOC Agent — sin Python ni PostgreSQL locales:

```bash
git clone https://github.com/cc22n/SOC-Assistan.git
cd SOC-Assistan

# Opcional pero recomendado: API keys + SECRET_KEY para el contenedor
cp .env.example .env.docker
# Edita .env.docker: define SECRET_KEY (32+ caracteres) y las API keys que tengas

docker compose up --build
```

Luego abre `http://localhost:5000`. El contenedor de la app espera a PostgreSQL, crea el esquema automáticamente (`db.create_all()` + índices de performance) y arranca gunicorn. El primer usuario registrado se convierte en administrador.

> Nota: sin API keys la app funciona, pero las consultas de IOCs devolverán resultados vacíos. `DATABASE_URL`, `REDIS_URL` y `FLASK_ENV` los define `docker-compose.yml` y siempre apuntan a los servicios incluidos.

### Instalación manual

### Prerrequisitos

- Python 3.10+
- PostgreSQL 14+
- Git

### 1. Clonar el repositorio

```bash
git clone https://github.com/your-username/soc-agent.git
cd soc-agent
```

### 2. Crear entorno virtual

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

### 3. Instalar dependencias

```bash
pip install -r requirements.txt
```

### 4. Configurar variables de entorno

```bash
cp .env.example .env
# Edita .env con tus API keys y configuración
```

### 5. Configurar PostgreSQL

```sql
CREATE DATABASE soc_agent;
CREATE USER soc_admin WITH PASSWORD 'tu_password_seguro';
GRANT ALL PRIVILEGES ON DATABASE soc_agent TO soc_admin;
```

### 6. Inicializar la base de datos

```bash
flask db upgrade

# Aplicar migraciones de performance y auditoría:
psql -U soc_admin -d soc_agent -f migrations/add_performance_indexes_and_audit.sql
```

### 7. Ejecutar la aplicación

```bash
# Desarrollo
flask run --debug

# Producción
gunicorn -w 4 -b 0.0.0.0:5000 wsgi:app
```

### 8. Crear una cuenta

Navega a `http://localhost:5000/auth/register`. El **primer usuario registrado se convierte en administrador** (bootstrap). Después, el registro es solo para admins: los administradores crean usuarios nuevos y les asignan rol desde el mismo formulario.

---

## Configuración de APIs

No necesitas todas las APIs para usar SOC Agent. El sistema funciona con las que tengas disponibles. APIs gratuitas recomendadas para empezar:

| API | Tier Gratuito | Registro |
|-----|---------------|----------|
| VirusTotal | 500 req/día | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| AbuseIPDB | 1000 req/día | [abuseipdb.com](https://www.abuseipdb.com/register) |
| GreyNoise | Community | [greynoise.io](https://viz.greynoise.io/signup) |
| AlienVault OTX | Ilimitado | [otx.alienvault.com](https://otx.alienvault.com/api) |
| Shodan InternetDB | Sin key | — |
| IP-API | Sin key | — |
| URLhaus | Sin key | — |
| ThreatFox | Sin key | — |
| MalwareBazaar | Sin key | — |
| IPGeolocation.io | 1000 req/día | [ipgeolocation.io](https://ipgeolocation.io/signup.html) |
| crt.sh | Sin key | — |
| Tavily (OSINT web) | 1000 créditos/mes | [tavily.com](https://app.tavily.com/) |

Para LLMs, [Groq](https://console.groq.com/) ofrece acceso gratuito. [Anthropic](https://console.anthropic.com/) y [OpenAI](https://platform.openai.com/) son de pago.

---

## Estructura del Proyecto

```
soc-agent/
├── app/
│   ├── __init__.py              # Factory pattern, logging JSON, hook de métricas
│   ├── config.py                # Config por entorno, modelos LLM
│   ├── middleware/
│   │   └── security.py          # Anti-SQLi, XSS, validación
│   ├── models/
│   │   ├── ioc.py               # User, IOC, IOCAnalysis, Incident
│   │   ├── session.py           # InvestigationSession, SessionIOC
│   │   ├── mitre.py             # Mapeos MITRE ATT&CK
│   │   └── audit.py             # AuditEvent, decorator @audit_action
│   ├── routes/
│   │   ├── main.py              # Vistas principales + dashboard de salud de APIs
│   │   ├── auth.py              # Login, registro, perfil (con audit log)
│   │   ├── api_v2_routes.py     # API REST (análisis, chat, sesiones, salud)
│   │   ├── incident_routes.py   # CRUD de incidentes con paginación + checks IDOR
│   │   ├── dashboard_routes.py  # API de estadísticas del dashboard
│   │   ├── report_routes.py     # Generación de reportes
│   │   └── mitre_stix_routes.py # MITRE + export STIX (protegido por RBAC)
│   ├── schemas/
│   │   ├── api.py               # Esquemas de request (Pydantic v2)
│   │   └── api_responses.py     # Esquemas de respuesta de APIs TI
│   ├── services/
│   │   ├── new_api_clients.py   # 20 clientes de API + Tavily, con circuit breakers
│   │   ├── llm_orchestrator.py  # Routing LLM, memoria del chat + grafo de correlación
│   │   ├── deep_analysis_service.py # Análisis profundo + agente de búsqueda de 2 pasos
│   │   ├── async_executor.py    # Ejecución paralela de APIs (asyncio)
│   │   ├── llm_service.py       # Comunicación LLM (5 proveedores)
│   │   ├── ioc_cache.py         # Caché con TTL por tipo y riesgo
│   │   ├── session_manager.py   # Gestión de sesiones de chat
│   │   ├── report_generator.py  # PDF y DOCX
│   │   └── dashboard_stats.py   # Estadísticas
│   ├── templates/               # Templates Jinja2
│   ├── docs/
│   │   └── openapi.py           # Especificación OpenAPI completa
│   └── utils/
│       ├── auth.py              # RBAC: decorator @require_role
│       ├── responses.py         # Helper compartido de errores 500 debug-gated
│       ├── circuit_breaker.py   # APICircuitBreaker (CLOSED/OPEN/HALF-OPEN)
│       ├── metrics.py           # Métricas de ventana deslizante P50/P95/P99
│       ├── security.py          # Sanitizador de prompt injection
│       ├── validators.py        # Validación de IOCs
│       └── formatters.py        # Formateo de datos
├── migrations/                  # Migraciones SQL
│   └── add_performance_indexes_and_audit.sql
├── tests/
│   └── unit/                    # Suite de tests pytest (375 tests)
├── .env.example                 # Plantilla de configuración
├── requirements.txt             # Dependencias Python
├── wsgi.py                      # Punto de entrada WSGI
└── README.md
```

---

## Stack Tecnológico

| Capa | Tecnología |
|------|------------|
| **Backend** | Python 3.12, Flask 3.0 |
| **Base de datos** | PostgreSQL 16 (JSONB, índices compuestos) |
| **ORM** | SQLAlchemy 2.x (Flask-SQLAlchemy) |
| **Validación** | Pydantic v2 (requests + respuestas de APIs) |
| **Frontend** | Jinja2, Tailwind CSS (CDN), Chart.js |
| **Autenticación** | Flask-Login, Werkzeug, roles RBAC |
| **Seguridad** | Flask-WTF (CSRF), Flask-Limiter, middleware propio, audit log |
| **Resiliencia** | Circuit breakers, caché TTL por tipo de IOC, métricas de requests |
| **Reportes** | ReportLab (PDF), python-docx (DOCX) |
| **APIs** | 20 APIs de Threat Intelligence + Tavily (OSINT web) |
| **IA** | 5 proveedores LLM con routing inteligente (xAI, OpenAI, Groq, Gemini, Anthropic) |

---

## Contribuir

¡Las contribuciones son bienvenidas! Abre issues o envía pull requests.

1. Haz fork del proyecto
2. Crea tu rama de feature (`git checkout -b feature/nueva-funcionalidad`)
3. Commitea tus cambios (`git commit -m 'Agrega nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Abre un Pull Request

---

## Licencia

Este proyecto está licenciado bajo la Licencia MIT. Ver [LICENSE](LICENSE) para más detalles.

---

## Autor

Construido como proyecto de portafolio demostrando habilidades en:
- Operaciones de Seguridad (SOC)
- Threat Intelligence
- Desarrollo de aplicaciones de seguridad
- Integración de APIs y LLMs
- Blue Team / Defensa

---

<div align="center">
<i>SOC Agent — Plataforma de Threat Intelligence con IA</i>
</div>
