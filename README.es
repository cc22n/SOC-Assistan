<div align="center">

# SOC assistan

### Plataforma de Threat Intelligence con IA para Analistas SOC

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-green?logo=flask&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-blue?logo=postgresql&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow)
![APIs](https://img.shields.io/badge/Threat_Intel_APIs-19-red)
![LLMs](https://img.shields.io/badge/LLM_Providers-4-purple)

*Analiza IOCs, genera reportes profesionales y gestiona incidentes de seguridad desde una sola interfaz.*

</div>

---

## Que es SOC assistant?

SOC Agent es una plataforma web de threat intelligence disenada para analistas de Security Operations Center (SOC). Integra **19 APIs de inteligencia de amenazas** y **4 proveedores LLM** para analizar Indicadores de Compromiso (IOCs) como IPs, dominios, hashes y URLs.

El sistema permite:
- Analizar IOCs contra multiples fuentes simultaneamente
- Obtener analisis inteligente con IA (LLM orchestration)
- Gestionar incidentes con vista Kanban y timeline
- Chatear con un asistente SOC que mantiene contexto de la investigacion
- Generar reportes profesionales en PDF y DOCX
- Correlacionar IOCs con tecnicas MITRE ATT&CK

---

## Arquitectura

```
┌─────────────────────────────────────────────────────┐
│                    Frontend                          │
│  Dashboard │ Analysis │ Chat │ Incidents │ Reports   │
│            (Jinja2 + Tailwind + Chart.js)            │
├─────────────────────────────────────────────────────┤
│                 Flask Backend                         │
│  ┌──────────┐ ┌──────────┐ ┌───────────────────┐    │
│  │ Auth     │ │ API v2   │ │ Security          │    │
│  │ (Login,  │ │ Routes   │ │ Middleware        │    │
│  │ Register)│ │          │ │ (Anti-SQLi, XSS)  │    │
│  └──────────┘ └──────────┘ └───────────────────┘    │
│  ┌──────────────────────────────────────────────┐    │
│  │           Services Layer                      │    │
│  │  LLM Orchestrator │ Session Manager           │    │
│  │  Threat Intel      │ Report Generator          │    │
│  │  Deep Analysis     │ Dashboard Stats           │    │
│  └──────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────────────────────┐    │
│  │ PostgreSQL  │  │ 19 Threat Intel APIs         │    │
│  │ (Users,     │  │ VirusTotal, AbuseIPDB,       │    │
│  │  IOCs,      │  │ Shodan, GreyNoise, OTX,      │    │
│  │  Analyses,  │  │ ThreatFox, URLhaus,           │    │
│  │  Incidents, │  │ MalwareBazaar, SecurityTrails, │    │
│  │  Sessions)  │  │ Pulsedive, URLScan, ...       │    │
│  └─────────────┘  └─────────────────────────────┘    │
│  ┌─────────────────────────────────────────────┐     │
│  │ 4 LLM Providers                              │     │
│  │ xAI (Grok) │ OpenAI (GPT-4) │ Groq │ Gemini │     │
│  └─────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────┘
```

---

## APIs Integradas

### Threat Intelligence (19)

| Categoria | APIs |
|-----------|------|
| **Reputacion** | VirusTotal, AbuseIPDB, GreyNoise, Pulsedive |
| **Infraestructura** | Shodan, Shodan InternetDB, Criminal IP, SecurityTrails |
| **Malware** | ThreatFox, MalwareBazaar, Hybrid Analysis |
| **URLs** | URLhaus, URLScan, Google Safe Browsing |
| **Inteligencia** | AlienVault OTX |
| **Geolocalizacion** | IP-API (gratuita, sin key) |

### LLM Providers (4)

| Proveedor | Modelo | Uso |
|-----------|--------|-----|
| **xAI** | Grok | Analisis rapido, default |
| **OpenAI** | GPT-4 | Analisis profundo |
| **Groq** | LLaMA / Mixtral | Velocidad, gratuito |
| **Gemini** | Gemini Pro | Alternativa Google |

---

## Funcionalidades

### Analisis de IOCs
- Analisis simultaneo contra multiples APIs
- Deteccion automatica del tipo de IOC (IP, dominio, hash, URL)
- Score de confianza y nivel de riesgo (CRITICO, ALTO, MEDIO, BAJO, LIMPIO)
- Mapeo automatico a tecnicas MITRE ATT&CK
- Selector de modelo LLM para el analisis

### Chat SOC con IA
- Asistente de investigacion con contexto persistente
- Sesiones de investigacion con historial
- Correlacion automatica de IOCs analizados en la sesion
- Exportacion de sesiones (JSON, Markdown, PDF, DOCX)

### Gestion de Incidentes
- Vista Kanban (Abierto, En Curso, Resuelto, Cerrado)
- Timeline integrado con mensajes del chat
- Multiples IOCs vinculados por incidente (tabla pivot)
- Ticket IDs automaticos (SOC-YYYYMMDD-NNN)
- Creacion rapida desde analisis o chat

### Dashboard
- Estadisticas en tiempo real con graficas
- Distribucion de riesgo, tendencias temporales
- IOCs recientes y incidentes abiertos
- Top IOCs mas analizados

### Reportes
- Generacion de PDF profesional con ReportLab
- Generacion de DOCX editable con python-docx
- Resumen ejecutivo, IOCs, MITRE ATT&CK, recomendaciones

### Seguridad
- Autenticacion con Flask-Login + password hashing (Werkzeug)
- Proteccion CSRF en todos los formularios
- Rate limiting por IP y endpoint
- Middleware anti-injection (SQLi, XSS, Command Injection, Path Traversal)
- Security headers (CSP, X-Frame-Options, HSTS, etc.)
- Session hardening (HttpOnly, SameSite, timeout)

---

## Instalacion

### Requisitos Previos

- Python 3.10+
- PostgreSQL 14+
- Git

### 1. Clonar el repositorio

```bash
git clone https://github.com/tu-usuario/soc-agent.git
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
# Editar .env con tus API keys y configuracion
```

### 5. Configurar PostgreSQL

```sql
-- Crear base de datos y usuario
CREATE DATABASE soc_agent;
CREATE USER soc_admin WITH PASSWORD 'tu_password_seguro';
GRANT ALL PRIVILEGES ON DATABASE soc_agent TO soc_admin;
```

### 6. Inicializar base de datos

```bash
flask db upgrade

# O ejecutar migraciones manualmente:
psql -U soc_admin -d soc_agent -f migrations/add_investigation_sessions.sql
psql -U soc_admin -d soc_agent -f migrations/add_new_api_fields_v3.sql
psql -U soc_admin -d soc_agent -f migrations/add_apis_v31_censys_ipinfo.sql
psql -U soc_admin -d soc_agent -f add_incidents_v31.sql
```

### 7. Ejecutar la aplicacion

```bash
# Desarrollo
flask run --debug

# Produccion
gunicorn -w 4 -b 0.0.0.0:5000 wsgi:app
```

### 8. Crear cuenta

Navega a `http://localhost:5000/auth/register`. El primer usuario se crea como **administrador**.

---

## Configuracion de APIs

No necesitas todas las APIs para usar SOC Agent. El sistema funciona con las que tengas disponibles. APIs gratuitas recomendadas para empezar:

| API | Gratuita | Registro |
|-----|----------|----------|
| VirusTotal | Si (500 req/dia) | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| AbuseIPDB | Si (1000 req/dia) | [abuseipdb.com](https://www.abuseipdb.com/register) |
| GreyNoise | Si (community) | [greynoise.io](https://viz.greynoise.io/signup) |
| AlienVault OTX | Si (ilimitada) | [otx.alienvault.com](https://otx.alienvault.com/api) |
| Shodan InternetDB | Si (sin key) | No requiere |
| IP-API | Si (sin key) | No requiere |
| URLhaus | Si (sin key) | No requiere |
| ThreatFox | Si (sin key) | No requiere |
| MalwareBazaar | Si (sin key) | No requiere |

Para LLMs, [Groq](https://console.groq.com/) ofrece acceso gratuito.

---

## Estructura del Proyecto

```
soc-agent/
├── app/
│   ├── __init__.py              # Factory pattern, config
│   ├── config.py                # Configuracion por entorno
│   ├── middleware/
│   │   └── security.py          # Anti-SQLi, XSS, validation
│   ├── models/
│   │   ├── ioc.py               # User, IOC, IOCAnalysis, Incident
│   │   ├── session.py           # InvestigationSession, SessionIOC
│   │   └── mitre.py             # MITRE ATT&CK mappings
│   ├── routes/
│   │   ├── main.py              # Vistas principales
│   │   ├── auth.py              # Login, registro, perfil
│   │   ├── api_v2_routes.py     # API REST (analisis, chat, sesiones)
│   │   ├── incident_routes.py   # CRUD de incidentes
│   │   ├── dashboard_routes.py  # Dashboard stats API
│   │   └── report_routes.py     # Generacion de reportes
│   ├── services/
│   │   ├── threat_intel.py      # Coordinador de APIs
│   │   ├── api_clients.py       # Clientes de 19 APIs
│   │   ├── llm_orchestrator.py  # Orquestacion de LLMs
│   │   ├── llm_service.py       # Comunicacion con LLMs
│   │   ├── session_manager.py   # Gestion de sesiones de chat
│   │   ├── report_generator.py  # PDF y DOCX
│   │   └── dashboard_stats.py   # Estadisticas
│   ├── templates/               # Jinja2 templates
│   │   ├── base.html            # Layout principal
│   │   ├── dashboard.html       # Dashboard con graficas
│   │   ├── analysis.html        # Analisis de IOCs
│   │   ├── chat.html            # Chat SOC con IA
│   │   ├── incidents.html       # Vista Kanban
│   │   ├── incident_detail.html # Detalle + timeline
│   │   └── auth/                # Login, registro, perfil
│   └── utils/
│       ├── validators.py        # Validacion de IOCs
│       └── formatters.py        # Formateo de datos
├── migrations/                  # SQL migrations
├── .env.example                 # Template de configuracion
├── requirements.txt             # Dependencias Python
├── wsgi.py                      # Entry point WSGI
└── README.md
```

---

## Stack Tecnologico

| Capa | Tecnologia |
|------|------------|
| **Backend** | Python 3.12, Flask 3.0 |
| **Base de Datos** | PostgreSQL 16 |
| **ORM** | SQLAlchemy (Flask-SQLAlchemy) |
| **Frontend** | Jinja2, Tailwind CSS (CDN), Chart.js |
| **Autenticacion** | Flask-Login, Werkzeug (password hashing) |
| **Seguridad** | Flask-WTF (CSRF), Flask-Limiter, Custom Middleware |
| **Reportes** | ReportLab (PDF), python-docx (DOCX) |
| **APIs** | 19 Threat Intelligence APIs |
| **IA** | 4 LLM providers (xAI, OpenAI, Groq, Gemini) |

---

## Licencia

Este proyecto esta bajo la licencia MIT. Ver [LICENSE](LICENSE) para mas detalles.

---

## Autor

Desarrollado como proyecto de portfolio para demostrar competencias en:
- Operaciones de seguridad (SOC)
- Threat Intelligence
- Desarrollo de aplicaciones de seguridad
- Integracion de APIs y LLMs
- Blue Team / Defensa

---

<div align="center">
<i>SOC Agent - Threat Intelligence Platform</i>
</div>
