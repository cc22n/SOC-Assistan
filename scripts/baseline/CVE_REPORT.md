# Línea base de CVE (WP3)

CVEs con respuestas: **92** (25 KEV, 27 sin KEV, 40 CTID).

Etiqueta = pertenencia a CISA KEV. **"Sin KEV" no es "no explotado"**: KEV es un catálogo incompleto.

### Nivel de riesgo (análisis completo)

| etiqueta | LIMPIO | BAJO | MEDIO | ALTO | CRÍTICO |
|---|---|---|---|---|---|
| kev | 0 | 0 | 0 | 5 | 20 |
| no_kev | 0 | 20 | 4 | 2 | 1 |

### ¿Cuánto predicen la pertenencia a KEV las señales que NO son KEV? (AUC)

- Score completo (incluye KEV, tautológico): **0.99**
- Score SIN el cliente KEV (CVSS + EPSS + Exploit-DB): **0.87**
- solo CVSS (NVD): 0.70
- solo EPSS: 0.93
- solo Exploit-DB: 0.65

### Cobertura de las APIs

| API | ok | error |
|---|---|---|
| nvd | 92 | 0 |
| cisa_kev | 92 | 0 |
| epss | 92 | 0 |
| exploitdb | 92 | 0 |

### Heurística MITRE (vector CVSS) frente al mapeo curado CTID — 40 CVEs

- **T1190**: aciertos=12, falsos positivos=14, omitidos=1  → precisión 46%, recall 92%
- **T1203**: aciertos=0, falsos positivos=3, omitidos=7  → precisión 0%, recall 0%
- **T1068**: aciertos=1, falsos positivos=3, omitidos=5  → precisión 25%, recall 17%