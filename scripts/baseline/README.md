# Línea base de calidad (fase 0.2 de PLAN-FUSION) — 2026-11-18

Mide cuánto acierta HOY el análisis de SOC Agent, para poder saber después si algún cambio lo mejora.

## Reproducir
```bash
python scripts/baseline/fetch_malicious.py   # maliciosos recientes de abuse.ch (necesita ABUSECH_AUTH_KEY) -> malicious_candidates.json (ignorado por git)
python scripts/baseline/build_dataset.py     # -> dataset.json (85 IOCs etiquetados; este SÍ se versiona: es la verdad de referencia)
python scripts/baseline/collect.py           # consulta las APIs reales (~20 min, límite de VirusTotal) -> tests/fixtures/baseline/snapshots.json
PYTHONIOENCODING=utf-8 python scripts/baseline/evaluate.py   # offline: -> REPORT.md y results.json
```
`evaluate.py` NO llama a ninguna API: tras cambiar el scoring basta reejecutarlo sobre las respuestas congeladas.
Para comparar un cambio, guarda `results.json` antes y después.

## Qué se mide (y qué no)
Solo la parte DETERMINISTA: `_calculate_enhanced_score` + `_determine_risk_level`, con la estrategia por defecto
de cada tipo y sin planificador LLM. El texto del LLM NO entra en el score (verificado en el código), así que su
calidad no está medida aquí.

## Lo que muestra (85 IOCs: 40 maliciosos, 34 benignos, 11 ambiguos)
1. **El score de un IOC limpio es casi todo "la API respondió".** El código suma +5 por cada API sin error aunque
   no diga nada malo: en benignos, 25.6 de 26.2 puntos (98 %) son de presencia. Con 6-7 APIs un dominio limpio
   parte de 30-35 → MEDIO.
2. **Dominios: el score no discrimina.** Medio 36.2 (maliciosos) vs 35.0 (benignos). A umbral MEDIO: 90 % de
   falsos positivos; a umbral ALTO: 0 % de recall.
3. **Hashes: bien** (100 % recall, 0 % FP a ALTO). **URLs**: 100 % a MEDIO, pero 20 % sin URLhaus/abuse.ch.
4. **IPs: 60 % de falsos negativos** (6 de 10 C2 recientes quedan en BAJO). La estrategia por defecto de IP no consulta
   ThreatFox (ni la de dominio); hay que comprobar si compensa añadirlo. Parte es inherente: un C2 de hoy aún
   no tiene reportes en AbuseIPDB.
5. **Nodos Tor → CRÍTICO (100)** por AbuseIPDB (reportes reales) + GreyNoise "malicious". Es un dato real, no un fallo
   del cliente; es decisión de producto si un nodo Tor debe ser CRÍTICO.
6. **Cobertura**: Pulsedive 23 % de éxito ("service temporarily unavailable" ×29), urlscan 56 % (HTTP 403 ×11),
   crt.sh 52 % (timeouts), Shodan 69 % ("Requires membership" para IPs). Un fallo de API no se distingue de
   "sin datos" en el score.

## Límites (leer antes de citar los números)
- n = 10 por celda: los porcentajes tienen mucho ruido (un IOC = 10 puntos).
- Etiqueta "maliciosa" = reportada por abuse.ch. Es circular para URLhaus/ThreatFox/MalwareBazaar:
  por eso `evaluate.py` repite todo SIN esas APIs (leave-source-out).
- Una sola fecha (2026-11-18). Los benignos son sitios muy populares (sesgo a favor); falta ruido realista.
- Los ambiguos no puntúan.
- Pulsedive/urlscan pudieron fallar por ráfaga de peticiones de la recolección, no por el servicio.

## Después del cambio de scoring (mismo día, mismas respuestas congeladas)
Se quitó el +5 por respuesta, VirusTotal pasó a bandas (1 motor=10, +3 por motor, tope 40; suspicious y reputación
negativa suman) y se añadió `api_coverage`. `results_before_2026-11-18.json` conserva los resultados anteriores.

| | antes | después |
|---|---|---|
| benignos marcados MEDIO o peor | 29 % (10/34) | **0 %** |
| AUC global (separa malicioso de benigno) | 0.89 | 0.92 |
| AUC dominios | 0.71 | **0.97** |
| AUC IPs | 0.76 | 0.70 |
| AUC URLs / hashes | 1.00 / 1.00 | 1.00 / 1.00 |
| recall a ALTO o peor (global) | 40 % | 32 % |
| recall a MEDIO o peor (global) | 85 % | 58 % |

Lectura honesta:
- Quitar la presencia elimina los falsos positivos por umbral, pero **por sí sola no mejora el ranking**: la mejora
  de AUC en dominios viene de VirusTotal (la señal ya estaba en la respuesta y se ignoraba).
- El recall BAJA porque antes parte del 'recall' era ruido (todo suma 30+). No es una pérdida de detección real.
- **IPs: el score sigue sin señal** (0 de 10 maliciosas a MEDIO). Ahí hay que añadir fuentes (ThreatFox en la
  estrategia de IP, OTX pulses con cuidado con Tor/CDN), no calibrar umbrales.
- Las bandas de VT se eligieron mirando estos datos (n pequeño): hay riesgo de sobreajuste. Repetir la línea base
  con otra fecha antes de darlas por definitivas.

## ThreatFox en las estrategias de IP y dominio (2026-11-18)
- ThreatFox busca por coincidencia PARCIAL: `google.com` devolvía 32 subdominios `google-proxy-...` y `github.com` URLs
  de malware alojado allí. Con la búsqueda cruda, 4 de 10 dominios benignos salían 'encontrados' (+30). `exact_match=true`
  no sirve para IPs (los IOC son `ip:puerto`). El cliente ahora filtra por igualdad exacta de tipo y valor.
- Con el filtro: **0 falsos positivos en 45 consultas de benignos y ambiguos**; encuentra 7/10 IPs y 9/10 dominios maliciosos.
- Análisis completo: AUC IPs 0.70 -> 0.95, recall IPs a MEDIO+ 0% -> 70%.
- **PERO es circular**: esos IOC están etiquetados maliciosos *porque* ThreatFox los lista. Sin las APIs de la fuente de la etiqueta
  (leave-source-out) el AUC de IPs sigue en 0.70. Este dataset NO demuestra mejora de detección independiente; demuestra
  que no añade falsos positivos y que el cliente funciona. Para medir la mejora real hace falta una etiqueta de otra fuente.
- `collect.py --add-api <api> --types ip,domain` añade una API a los snapshots sin repetir las demás.

## CVE (WP3, 2026-11-19) — `cve_baseline.py build|collect|evaluate`, informe en `CVE_REPORT.md`
92 CVEs reales (25 KEV, 27 sin KEV, 40 con mapeo CTID); respuestas en `tests/fixtures/baseline/cve_snapshots.json`.
Las 4 APIs respondieron 92/92. La etiqueta es la pertenencia a CISA KEV (**sin KEV no es 'no explotado'**: KEV es incompleto).

| qué predice KEV (AUC) | valor |
|---|---|
| solo EPSS | 0.93 |
| solo CVSS (NVD) | 0.70 |
| solo Exploit-DB | 0.65 |
| score SIN el cliente KEV (antes de recalibrar EPSS 20/10) | 0.82 |
| score SIN el cliente KEV (EPSS 30/20/8, vigente) | **0.87** |

- **EPSS es la señal que mejor separa** (mediana 0.35 en KEV vs 0.009 fuera); CVSS y Exploit-DB diluían la mezcla.
  Se subieron sus puntos y se añadió un escalón bajo. Riesgo de sobreajuste (n=52): repetir con otra muestra.
- **Heurística MITRE** frente a CTID (40 CVEs): T1190 recall 92 % / precisión 46 % (cota inferior, CTID lista pocas
  técnicas); **T1203 (0/3 aciertos) y T1068 (25 %/17 %) se eliminaron** por no tener respaldo.
- CTID cubre solo el 11 % de KEV y 0 % de 2023+: para CVEs modernos las técnicas casi siempre son heurísticas.
- Limitación general: KEV y EPSS no son independientes (EPSS se entrena con observaciones de explotación).

## Feeds proactivos (WP6, 2026-11-19) - evidencia previa y medida
Verificado EN VIVO antes de diseñar (fixtures reales en `tests/fixtures/feeds/`):
- SOC Agent no tenía planificador y Gunicorn arranca 3 workers -> servicio `feeds` aparte, no Celery ni APScheduler en la app.
- NVD, CVE recién publicado: **204 de 204 sin configuraciones CPE** (llegan días después), pero el **100 % trae vendor/producto**
  en `affected[].affectedData[]` de la CNA: de ahí se casa. EPSS no puntúa a los de <1 día (1 de 8 devueltos).
- Volumen: unos 100 CVE graves/día en NVD (204 en 48 h) y 38 altas en KEV en 30 días. **120 de los 204 (59 %) son de Oracle**
  (su parche trimestral): sin filtro por stack el feed sería ruido.
  **CORRECCIÓN**: una versión anterior de este análisis decía '127 de Oracle y 89 de Red Hat'. Era un conteo de pares
  vendor/producto, no de CVE (un solo CVE lista muchos productos). Lo correcto: Oracle 120 CVE, Red Hat ~1.
- Casado probado contra el catálogo KEV real (1 786 entradas): 0 falsos positivos de `go`; `log4j`->`Log4j2`; FortiOS y sus
  variantes se agrupan. Límites DOCUMENTADOS: una entrada solo de producto (`IOS`) casa Cisco IOS y Apple iOS (79 CVE) y `Office`
  casa `WPS Office`; declarar también el vendor lo evita. No se casa por el texto de la descripción.
- Ejecución real (sin mocks): 242 CVE en 18 s; con un stack de 3 entradas **11 son relevantes (4.5 %)**; añadir `Oracle` sube a 131
  (= 11 + 120) y quitarlo vuelve a 11. Segunda ejecución: 0 nuevos (idempotente).
- Hallazgo de la primera ejecución real: los CVE de KEV recién añadidos puntuaban 40 (MEDIO) porque KEV no trae CVSS y EPSS
  llega con retraso -> **suelo: KEV = ALTO como mínimo**.
- Fuera de v1 (a propósito): OTX/RSS/URLhaus, resumen diario con LLM, notificaciones externas, estado leído/descartado por usuario.

## Repaso del 2026-11-19: auditoría independiente de lo añadido (3 agentes, hallazgos verificados uno a uno)
Se verificó cada hallazgo con código o ejecución antes de actuar; el resumen de cuántos eran reales está en la bitácora.
- Corregidos y con test (cada uno detecta su mutación): F1 perfiles huérfanos colisionaban al borrar usuarios (REPRODUCIDO; migración
  b7c9d1e3f5a6 -> CASCADE); F4 relevancia desfasada si el stack cambia durante una ejecución (se reconcilia al final);
  F5 conexión del lock 'idle in transaction' (AUTOCOMMIT); F6 ejecuciones 'running' fantasma tras un kill -9;
  F7 alta de stack devolvía 500 aunque ya estaba guardada; R2 reintento cada 5 min sin espera tras un fallo (ahora 30 min);
  S-2 catálogo caído hacía cola de N x timeout (enfriamiento de 60 s); S-3 `locked_accounts` hacía 1+2 consultas por nombre
  (prefiltro HAVING >= umbral); S-1 fixtures con correos de personas, claves AIza de terceros, oobCode y cookies (REDACTADOS).
- NO eran reales / mal leídos por los agentes: 'profile_id y entry_id no están en la matriz de autorización' (están, 17 casos).
- Aceptados sin cambio (documentado): F3 límites 50/200 son check-then-insert (acotados por rate limit; efecto cosmético);
  F8 N+1 en el upsert (proceso de fondo); R3 sin `mem_limit` en compose (medido: Exploit-DB ~72 MB de pico por proceso;
  dimensionar en el VPS); R5 logs de `feeds` en el sistema de archivos del contenedor.
- Para el VPS (acciones del usuario): definir NVD_API_KEY, ALLOWED_HOSTS, DEEPSEEK/KIMI y POSTGRES_PASSWORD en `.env.docker`,
  proxy con TLS en el host y probar un restore real de un backup.

## Línea base repetida con otra muestra y etiquetas INDEPENDIENTES (2026-11-19)
`BASELINE_TAG=_2026-11-19` (dataset/snapshots/results/REPORT con ese sufijo; la del 18 queda intacta). 105 IOCs: los 45 benignos y
ambiguos son los mismos; **los 60 maliciosos son TODOS nuevos**: 40 de abuse.ch (circulares) y 20 de fuentes ajenas a abuse.ch:
CINS Army (5 IP) y Emerging Threats (5 IP) como listas negras, y OpenPhish (10 URL de phishing).

| AUC (malicioso vs benigno) | 18-nov | 19-nov |
|---|---|---|
| global, análisis completo | 0.99 | 0.97 |
| global, SIN la fuente de la etiqueta | 0.92 | 0.91 |
| IPs, SIN la fuente de la etiqueta | 0.70 | 0.75 |
| dominios, SIN la fuente de la etiqueta | 0.97 | 0.97 |
| URLs / hashes | 1.00 / 1.00 | 1.00 / 1.00 |
| **solo etiqueta independiente: IPs (CINS + ET)** | - | **0.95** |
| **solo etiqueta independiente: URLs (OpenPhish)** | - | **1.00** |

- **Las bandas de VirusTotal NO sobreajustaron**: con una muestra distinta de maliciosos el AUC se mantiene.
- **Falsos positivos: 0 de 34 benignos** otra vez (sin umbral ni distinguir tipos).
- **Recall real (etiquetas independientes), umbral MEDIO o peor: IPs 70 % (ET 100 %, CINS 40 %), URLs de phishing 90 %**; a ALTO o peor
  solo 30 % y 10 %. El umbral efectivo de alerta es MEDIO (score >= 30): con él hay 0 falsos positivos en los 34 benignos.
  CINS recoge sobre todo escáneres y fuerza bruta (poco reportados en AbuseIPDB), por eso rinde menos que las IP de Emerging Threats.
- El AUC es alto pero el recall a umbral es menor: el RANKING separa bien, los puntos son conservadores (sobre todo para IPs y dominios).
- **LÍMITE de esta repetición: cuotas gratuitas agotadas.** Dos recolecciones completas el mismo día agotan Criminal IP (`limit exceeded`
  desde la primera consulta: 0/36 ok) y Pulsedive (`50 requests per day`: 6/82 ok); Shodan exige membresía para IPs y urlscan da 403.
  El texto 'service temporarily unavailable' de la tabla de cobertura es NUESTRO circuit breaker abierto, no cuatro proveedores caídos.
  Las IPs de hoy se puntuaron SIN Criminal IP: el recall de IPs es una cota inferior de un día normal.
- Pendiente: dominios con etiqueta independiente (ninguna fuente usada aquí; sin la de abuse.ch los dominios de hoy quedan en BAJO).

Regla práctica: una recolección completa por día como máximo (o `--limit`); la repetición ya hecha sirve de referencia.
