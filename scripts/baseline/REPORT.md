# Línea base de calidad del análisis (fase 0.2 de PLAN-FUSION)

IOCs evaluados: **85** de 85 del dataset. Respuestas reales congeladas en `tests/fixtures/baseline/snapshots.json`. Se mide el scoring determinista actual (`_calculate_enhanced_score`); el texto del LLM no entra en el score.

Composición: malicious=40, benign=34, ambiguous=11

### Nivel de riesgo asignado (análisis completo)

| etiqueta | LIMPIO | BAJO | MEDIO | ALTO | CRÍTICO | n |
|---|---|---|---|---|---|---|
| malicious | 0 | 6 | 18 | 7 | 9 | 40 |
| benign | 0 | 24 | 9 | 1 | 0 | 34 |
| ambiguous | 0 | 2 | 2 | 1 | 6 | 11 |

### Nivel de riesgo SIN las APIs de la fuente de la etiqueta (leave-source-out, solo maliciosos son afectados)

| etiqueta | LIMPIO | BAJO | MEDIO | ALTO | CRÍTICO | n |
|---|---|---|---|---|---|---|
| malicious | 0 | 17 | 11 | 5 | 7 | 40 |
| benign | 0 | 24 | 9 | 1 | 0 | 34 |
| ambiguous | 0 | 2 | 2 | 1 | 6 | 11 |

### Alerta = ALTO o CRÍTICO (score ≥ 50), análisis completo

| tipo | recall maliciosos | falsos positivos (benignos) | precisión | n mal / n ben |
|---|---|---|---|---|
| ALL | 40% (16/40) | 3% (1/34) | 94% | 40 / 34 |
| ip | 30% (3/10) | 0% (0/8) | 100% | 10 / 8 |
| domain | 0% (0/10) | 10% (1/10) | 0% | 10 / 10 |
| url | 30% (3/10) | 0% (0/8) | 100% | 10 / 8 |
| hash | 100% (10/10) | 0% (0/8) | 100% | 10 / 8 |

### Alerta = MEDIO o peor (score ≥ 30), análisis completo

| tipo | recall maliciosos | falsos positivos (benignos) | precisión | n mal / n ben |
|---|---|---|---|---|
| ALL | 85% (34/40) | 29% (10/34) | 77% | 40 / 34 |
| ip | 40% (4/10) | 0% (0/8) | 100% | 10 / 8 |
| domain | 100% (10/10) | 90% (9/10) | 53% | 10 / 10 |
| url | 100% (10/10) | 0% (0/8) | 100% | 10 / 8 |
| hash | 100% (10/10) | 12% (1/8) | 91% | 10 / 8 |

### Alerta = ALTO o CRÍTICO, SIN APIs de la fuente de la etiqueta

| tipo | recall maliciosos | falsos positivos (benignos) | precisión | n mal / n ben |
|---|---|---|---|---|
| ALL | 30% (12/40) | 3% (1/34) | 92% | 40 / 34 |
| ip | 30% (3/10) | 0% (0/8) | 100% | 10 / 8 |
| domain | 0% (0/10) | 10% (1/10) | 0% | 10 / 10 |
| url | 0% (0/10) | 0% (0/8) | n/a | 10 / 8 |
| hash | 90% (9/10) | 0% (0/8) | 100% | 10 / 8 |

### Alerta = MEDIO o peor, SIN APIs de la fuente de la etiqueta

| tipo | recall maliciosos | falsos positivos (benignos) | precisión | n mal / n ben |
|---|---|---|---|---|
| ALL | 58% (23/40) | 29% (10/34) | 70% | 40 / 34 |
| ip | 40% (4/10) | 0% (0/8) | 100% | 10 / 8 |
| domain | 80% (8/10) | 90% (9/10) | 47% | 10 / 10 |
| url | 20% (2/10) | 0% (0/8) | 100% | 10 / 8 |
| hash | 90% (9/10) | 12% (1/8) | 90% | 10 / 8 |

### ¿Cuánto del score de un IOC limpio es solo "la API respondió"? (+5 por API sin error)

Benignos: score medio **26.2**, de los cuales **25.6** son puntos de presencia (98%). Benignos que subirían de nivel solo por estos puntos: 33 de 34.

### Falsos positivos (benignos con nivel ≥ MEDIO)

- `github.com` (domain, sitio_legitimo) score=55 ALTO (presencia 35)
- `google.com` (domain, sitio_legitimo) score=35 MEDIO (presencia 35)
- `microsoft.com` (domain, sitio_legitimo) score=35 MEDIO (presencia 35)
- `mozilla.org` (domain, sitio_legitimo) score=35 MEDIO (presencia 35)
- `debian.org` (domain, sitio_legitimo) score=35 MEDIO (presencia 35)
- `apache.org` (domain, sitio_legitimo) score=35 MEDIO (presencia 35)
- `cloudflare.com` (domain, sitio_legitimo) score=35 MEDIO (presencia 35)
- `python.org` (domain, sitio_legitimo) score=30 MEDIO (presencia 30)
- `kernel.org` (domain, sitio_legitimo) score=30 MEDIO (presencia 30)
- `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852` (hash, SHA-256 del archivo vacío (lo conoce todo el mundo)) score=30 MEDIO (presencia 30)

### Falsos negativos (maliciosos con nivel ≤ BAJO, análisis completo)

- `217.216.54.78` (ip, malware=AsyncRAT conf=100) score=20 BAJO  [4/6 APIs ok]
- `216.73.157.144` (ip, malware=Cobalt Strike conf=100) score=25 BAJO  [5/6 APIs ok]
- `14.102.238.105` (ip, malware=Unknown malware conf=100) score=25 BAJO  [5/6 APIs ok]
- `160.202.46.32` (ip, malware=Cobalt Strike conf=100) score=25 BAJO  [5/6 APIs ok]
- `31.77.168.157` (ip, malware=Unknown malware conf=100) score=25 BAJO  [5/6 APIs ok]
- `192.163.172.91` (ip, malware=Unknown malware conf=100) score=25 BAJO  [5/6 APIs ok]

### Ambiguos (informativo, no puntúa)

- `171.25.193.25` (nodo_tor) score=100 CRÍTICO
- `80.67.167.81` (nodo_tor) score=100 CRÍTICO
- `109.70.100.4` (nodo_tor) score=100 CRÍTICO
- `192.42.116.99` (nodo_tor) score=100 CRÍTICO
- `192.42.116.44` (nodo_tor) score=100 CRÍTICO
- `71.6.135.131` (escaner_internet) score=85 CRÍTICO
- `pastebin.com` (servicio_doble_uso) score=50 ALTO
- `duckdns.org` (servicio_doble_uso) score=35 MEDIO
- `ngrok.io` (servicio_doble_uso) score=30 MEDIO
- `162.142.125.10` (escaner_internet) score=25 BAJO
- `198.20.69.74` (escaner_internet) score=25 BAJO

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
| urlhaus | 41 | 0 | 100% |  |
| securitytrails | 23 | 0 | 100% |  |
| virustotal | 59 | 0 | 100% |  |
| google_safebrowsing | 41 | 0 | 100% |  |
| threatfox | 18 | 0 | 100% |  |
| hybrid_analysis | 18 | 0 | 100% |  |
| malwarebazaar | 18 | 0 | 100% |  |
