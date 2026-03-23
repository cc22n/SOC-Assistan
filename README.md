<div align="center">

# SOC Assistan

### AI-Powered Threat Intelligence Platform for SOC Analysts

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-green?logo=flask&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-blue?logo=postgresql&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow)
![APIs](https://img.shields.io/badge/Threat_Intel_APIs-19-red)
![LLMs](https://img.shields.io/badge/LLM_Providers-4-purple)

*Analyze IOCs, generate professional reports, and manage security incidents from a single interface.*

[Spanish Version / Version en Espanol](README.es.md)

</div>

---

## What is SOC Assistan?

SOC Assistan is a web-based threat intelligence platform designed for Security Operations Center (SOC) analysts. It integrates **19 threat intelligence APIs** and **4 LLM providers** to analyze Indicators of Compromise (IOCs) such as IPs, domains, hashes, and URLs.

The system enables analysts to:
- Analyze IOCs against multiple sources simultaneously
- Get AI-powered intelligent analysis (LLM orchestration)
- Manage incidents with Kanban board and timeline views
- Chat with an AI SOC assistant that maintains investigation context
- Generate professional reports in PDF and DOCX formats
- Correlate IOCs with MITRE ATT&CK techniques

---

## Architecture

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

## Integrated APIs

### Threat Intelligence (19)

| Category | APIs |
|----------|------|
| **Reputation** | VirusTotal, AbuseIPDB, GreyNoise, Pulsedive |
| **Infrastructure** | Shodan, Shodan InternetDB, Criminal IP, SecurityTrails |
| **Malware** | ThreatFox, MalwareBazaar, Hybrid Analysis |
| **URLs** | URLhaus, URLScan, Google Safe Browsing |
| **Intelligence** | AlienVault OTX |
| **Geolocation** | IP-API (free, no key required) |

### LLM Providers (4)

| Provider | Model | Use Case |
|----------|-------|----------|
| **xAI** | Grok | Fast analysis, default |
| **OpenAI** | GPT-4 | Deep analysis |
| **Groq** | LLaMA / Mixtral | Speed, free tier |
| **Gemini** | Gemini Pro | Google alternative |

---

## Features

### IOC Analysis
- Simultaneous analysis against multiple APIs
- Automatic IOC type detection (IP, domain, hash, URL)
- Confidence score and risk level (CRITICAL, HIGH, MEDIUM, LOW, CLEAN)
- Automatic MITRE ATT&CK technique mapping
- LLM model selector for analysis

### AI SOC Chat
- Investigation assistant with persistent context
- Investigation sessions with full history
- Automatic correlation of IOCs analyzed in the session
- Session export (JSON, Markdown, PDF, DOCX)

### Incident Management
- Kanban board view (Open, Investigating, Resolved, Closed)
- Integrated timeline with chat messages
- Multiple IOCs linked per incident (pivot table)
- Auto-generated ticket IDs (SOC-YYYYMMDD-NNN)
- Quick creation from analysis or chat

### Dashboard
- Real-time statistics with charts
- Risk distribution, temporal trends
- Recent IOCs and open incidents
- Top analyzed IOCs

### Reports
- Professional PDF generation with ReportLab
- Editable DOCX generation with python-docx
- Executive summary, IOCs, MITRE ATT&CK, recommendations

### Security
- Authentication with Flask-Login + password hashing (Werkzeug)
- CSRF protection on all forms
- Rate limiting by IP and endpoint
- Anti-injection middleware (SQLi, XSS, Command Injection, Path Traversal)
- Security headers (CSP, X-Frame-Options, HSTS, etc.)
- Session hardening (HttpOnly, SameSite, timeout)

---

## Installation

### Prerequisites

- Python 3.10+
- PostgreSQL 14+
- Git

### 1. Clone the repository

```bash
git clone https://github.com/your-username/soc-agent.git
cd soc-agent
```

### 2. Create virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

```bash
cp ..env.example .env
# Edit .env with your API keys and configuration
```

### 5. Set up PostgreSQL

```sql
CREATE DATABASE soc_agent;
CREATE USER soc_admin WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE soc_agent TO soc_admin;
```

### 6. Initialize database

```bash
flask db upgrade

# Or run migrations manually:
psql -U soc_admin -d soc_agent -f migrations/add_investigation_sessions.sql
psql -U soc_admin -d soc_agent -f migrations/add_new_api_fields_v3.sql
psql -U soc_admin -d soc_agent -f migrations/add_apis_v31_censys_ipinfo.sql
psql -U soc_admin -d soc_agent -f add_incidents_v31.sql
```

### 7. Run the application

```bash
# Development
flask run --debug

# Production
gunicorn -w 4 -b 0.0.0.0:5000 wsgi:app
```

### 8. Create an account

Navigate to `http://localhost:5000/auth/register`. The first registered user becomes **administrator**.

---

## API Configuration

You don't need all APIs to use SOC Agent. The system works with whatever APIs you have available. Recommended free APIs to get started:

| API | Free Tier | Sign Up |
|-----|-----------|---------|
| VirusTotal | Yes (500 req/day) | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| AbuseIPDB | Yes (1000 req/day) | [abuseipdb.com](https://www.abuseipdb.com/register) |
| GreyNoise | Yes (community) | [greynoise.io](https://viz.greynoise.io/signup) |
| AlienVault OTX | Yes (unlimited) | [otx.alienvault.com](https://otx.alienvault.com/api) |
| Shodan InternetDB | Yes (no key) | Not required |
| IP-API | Yes (no key) | Not required |
| URLhaus | Yes (no key) | Not required |
| ThreatFox | Yes (no key) | Not required |
| MalwareBazaar | Yes (no key) | Not required |

For LLMs, [Groq](https://console.groq.com/) offers free access.

---

## Project Structure

```
soc-agent/
├── app/
│   ├── __init__.py              # Factory pattern, config
│   ├── config.py                # Environment-based config
│   ├── middleware/
│   │   └── security.py          # Anti-SQLi, XSS, validation
│   ├── models/
│   │   ├── ioc.py               # User, IOC, IOCAnalysis, Incident
│   │   ├── session.py           # InvestigationSession, SessionIOC
│   │   └── mitre.py             # MITRE ATT&CK mappings
│   ├── routes/
│   │   ├── main.py              # Main views
│   │   ├── auth.py              # Login, register, profile
│   │   ├── api_v2_routes.py     # REST API (analysis, chat, sessions)
│   │   ├── incident_routes.py   # Incident CRUD
│   │   ├── dashboard_routes.py  # Dashboard stats API
│   │   └── report_routes.py     # Report generation
│   ├── services/
│   │   ├── threat_intel.py      # API coordinator
│   │   ├── api_clients.py       # 19 API clients
│   │   ├── llm_orchestrator.py  # LLM orchestration
│   │   ├── llm_service.py       # LLM communication
│   │   ├── session_manager.py   # Chat session management
│   │   ├── report_generator.py  # PDF and DOCX
│   │   └── dashboard_stats.py   # Statistics
│   ├── templates/               # Jinja2 templates
│   └── utils/
│       ├── validators.py        # IOC validation
│       └── formatters.py        # Data formatting
├── migrations/                  # SQL migrations
├── .env.example                 # Configuration template
├── requirements.txt             # Python dependencies
├── wsgi.py                      # WSGI entry point
└── README.md
```

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| **Backend** | Python 3.12, Flask 3.0 |
| **Database** | PostgreSQL 16 |
| **ORM** | SQLAlchemy (Flask-SQLAlchemy) |
| **Frontend** | Jinja2, Tailwind CSS (CDN), Chart.js |
| **Authentication** | Flask-Login, Werkzeug (password hashing) |
| **Security** | Flask-WTF (CSRF), Flask-Limiter, Custom Middleware |
| **Reports** | ReportLab (PDF), python-docx (DOCX) |
| **APIs** | 19 Threat Intelligence APIs |
| **AI** | 4 LLM providers (xAI, OpenAI, Groq, Gemini) |

---

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/new-feature`)
3. Commit your changes (`git commit -m 'Add new feature'`)
4. Push to the branch (`git push origin feature/new-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## Author

Built as a portfolio project demonstrating skills in:
- Security Operations (SOC)
- Threat Intelligence
- Security application development
- API and LLM integration
- Blue Team / Defense

---

<div align="center">
<i>SOC Assistan - AI-Powered Threat Intelligence Platform</i>
</div>
