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
