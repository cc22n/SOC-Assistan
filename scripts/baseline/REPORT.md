# Línea base de calidad del análisis (fase 0.2 de PLAN-FUSION)

IOCs evaluados: **85** de 85 del dataset. Respuestas reales congeladas en `tests/fixtures/baseline/snapshots.json`. Se mide el scoring determinista actual (`_calculate_enhanced_score`); el texto del LLM no entra en el score.

Composición: malicious=40, benign=34, ambiguous=11

### Nivel de riesgo asignado (análisis completo)

| etiqueta | LIMPIO | BAJO | MEDIO | ALTO | CRÍTICO | n |
|---|---|---|---|---|---|---|
| malicious | 1 | 3 | 15 | 10 | 11 | 40 |
| benign | 33 | 1 | 0 | 0 | 0 | 34 |
| ambiguous | 2 | 2 | 1 | 1 | 5 | 11 |

### Nivel de riesgo SIN las APIs de la fuente de la etiqueta (leave-source-out, solo maliciosos son afectados)

| etiqueta | LIMPIO | BAJO | MEDIO | ALTO | CRÍTICO | n |
|---|---|---|---|---|---|---|
| malicious | 6 | 18 | 5 | 11 | 0 | 40 |
| benign | 33 | 1 | 0 | 0 | 0 | 34 |
| ambiguous | 2 | 2 | 1 | 1 | 5 | 11 |

### Alerta = ALTO o CRÍTICO (score ≥ 50), análisis completo

| tipo | recall maliciosos | falsos positivos (benignos) | precisión | n mal / n ben |
|---|---|---|---|---|
| ALL | 52% (21/40) | 0% (0/34) | 100% | 40 / 34 |
| ip | 20% (2/10) | 0% (0/8) | 100% | 10 / 8 |
| domain | 60% (6/10) | 0% (0/10) | 100% | 10 / 10 |
| url | 40% (4/10) | 0% (0/8) | 100% | 10 / 8 |
| hash | 90% (9/10) | 0% (0/8) | 100% | 10 / 8 |

### Alerta = MEDIO o peor (score ≥ 30), análisis completo

| tipo | recall maliciosos | falsos positivos (benignos) | precisión | n mal / n ben |
|---|---|---|---|---|
| ALL | 90% (36/40) | 0% (0/34) | 100% | 40 / 34 |
| ip | 70% (7/10) | 0% (0/8) | 100% | 10 / 8 |
| domain | 90% (9/10) | 0% (0/10) | 100% | 10 / 10 |
| url | 100% (10/10) | 0% (0/8) | 100% | 10 / 8 |
| hash | 100% (10/10) | 0% (0/8) | 100% | 10 / 8 |

### Alerta = ALTO o CRÍTICO, SIN APIs de la fuente de la etiqueta

| tipo | recall maliciosos | falsos positivos (benignos) | precisión | n mal / n ben |
|---|---|---|---|---|
| ALL | 28% (11/40) | 0% (0/34) | 100% | 40 / 34 |
| ip | 0% (0/10) | 0% (0/8) | n/a | 10 / 8 |
| domain | 0% (0/10) | 0% (0/10) | n/a | 10 / 10 |
| url | 20% (2/10) | 0% (0/8) | 100% | 10 / 8 |
| hash | 90% (9/10) | 0% (0/8) | 100% | 10 / 8 |

### Alerta = MEDIO o peor, SIN APIs de la fuente de la etiqueta

| tipo | recall maliciosos | falsos positivos (benignos) | precisión | n mal / n ben |
|---|---|---|---|---|
| ALL | 40% (16/40) | 0% (0/34) | 100% | 40 / 34 |
| ip | 0% (0/10) | 0% (0/8) | n/a | 10 / 8 |
| domain | 30% (3/10) | 0% (0/10) | 100% | 10 / 10 |
| url | 40% (4/10) | 0% (0/8) | 100% | 10 / 8 |
| hash | 90% (9/10) | 0% (0/8) | 100% | 10 / 8 |

### Falsos positivos (benignos con nivel ≥ MEDIO)

- ninguno

### Falsos negativos (maliciosos con nivel ≤ BAJO, análisis completo)

- `134.175.236.45` (ip, malware=Unknown malware conf=100) score=25 BAJO  [6/7 APIs ok]
- `43.128.108.9` (ip, malware=Unknown malware conf=100) score=25 BAJO  [6/7 APIs ok]
- `192.163.172.91` (ip, malware=Unknown malware conf=100) score=0 LIMPIO  [6/7 APIs ok]
- `emprdrcfhpvym7uwqvxky6ympquibzxfxuor6qeexk7lz3sxz5t2ubqd.onion` (domain, malware=Unknown malware conf=100) score=24 BAJO  [8/8 APIs ok]

### Ambiguos (informativo, no puntúa)

- `192.42.116.99` (nodo_tor) score=95 CRÍTICO
- `192.42.116.44` (nodo_tor) score=95 CRÍTICO
- `171.25.193.25` (nodo_tor) score=80 CRÍTICO
- `80.67.167.81` (nodo_tor) score=80 CRÍTICO
- `109.70.100.4` (nodo_tor) score=80 CRÍTICO
- `71.6.135.131` (escaner_internet) score=65 ALTO
- `pastebin.com` (servicio_doble_uso) score=30 MEDIO
- `ngrok.io` (servicio_doble_uso) score=12 BAJO
- `duckdns.org` (servicio_doble_uso) score=10 BAJO
- `162.142.125.10` (escaner_internet) score=0 LIMPIO
- `198.20.69.74` (escaner_internet) score=0 LIMPIO

### Cobertura de APIs (respuestas reales)

| API | ok | error | tasa de éxito | error más frecuente |
|---|---|---|---|---|
| pulsedive | 14 | 48 | 23% | service temporarily unavailable (×29) |
| crtsh | 12 | 11 | 52% | Timeout (30.0s) (×8) |
| urlscan | 23 | 18 | 56% | HTTP 403 (×11) |
| shodan | 18 | 8 | 69% | Requires membership or higher to access (×8) |
| otx | 64 | 3 | 96% | Timeout (30.0s) (×3) |
| greynoise | 26 | 0 | 100% |  |
| abuseipdb | 26 | 0 | 100% |  |
| criminal_ip | 26 | 0 | 100% |  |
| threatfox | 67 | 0 | 100% |  |
| urlhaus | 41 | 0 | 100% |  |
| securitytrails | 23 | 0 | 100% |  |
| virustotal | 59 | 0 | 100% |  |
| google_safebrowsing | 41 | 0 | 100% |  |
| hybrid_analysis | 18 | 0 | 100% |  |
| malwarebazaar | 18 | 0 | 100% |  |

### Recall de maliciosos por fuente de la etiqueta (ALTO o peor | MEDIO o peor)

| fuente de la etiqueta | tipo | n | ALTO+ | MEDIO+ | independiente de abuse.ch |
|---|---|---|---|---|---|
| malwarebazaar | hash | 10 | 90% (9) | 100% (10) | no (circular) |
| threatfox | ip | 20 | 40% (8) | 80% (16) | no (circular) |
| urlhaus | url | 10 | 40% (4) | 100% (10) | no (circular) |
