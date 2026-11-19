"""
Técnicas MITRE ATT&CK relacionadas con un CVE (WP3 de PLAN-FUSION).

Dos fuentes, y SIEMPRE se indica de cuál viene cada técnica (`source`), para no presentar una suposición como un dato:

  * 'ctid'           mapeo curado del Center for Threat-Informed Defense (app/data/attack_to_cve.csv, Apache-2.0,
                     https://github.com/center-for-threat-informed-defense/attack_to_cve). Es la fuente fiable, pero
                     su cobertura es pequeña: 836 CVE (2008-2020), el 11 % del catálogo KEV y 0 % de los CVE de 2023
                     en adelante (medido el 2026-11-19).
  * 'heuristic_cvss' UNA regla (T1190) a partir del vector CVSS de NVD. Es una APROXIMACIÓN, no un mapeo curado.
                     Medida contra CTID en 40 CVEs: recall 92 %, precisión 46 % (cota inferior: CTID lista pocas
                     técnicas por CVE). Se probaron además T1203 (0 de 3 aciertos, 0 de 7 recuperados) y T1068 (25 % de
                     precisión, 17 % de recall) y se ELIMINARON por no tener respaldo (scripts/baseline/CVE_REPORT.md).

Si hay mapeo CTID se usa SOLO ese (no se añade la heurística encima).
"""
import csv
import re
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

_DATA = Path(__file__).resolve().parent.parent / 'data' / 'attack_to_cve.csv'
_TECH = re.compile(r'T\d{4}(?:\.\d{3})?')
_lock = threading.Lock()
_index: Optional[Dict[str, List[str]]] = None


def _load() -> Dict[str, List[str]]:
    global _index
    if _index is None:
        with _lock:
            if _index is None:
                idx: Dict[str, List[str]] = {}
                with open(_DATA, encoding='utf-8-sig', newline='') as f:
                    for row in csv.DictReader(f):
                        cve = (row.get('CVE ID') or '').strip().upper()
                        if not cve:
                            continue
                        techs: List[str] = []
                        for col in ('Primary Impact', 'Secondary Impact', 'Exploitation Technique', 'Uncategorized'):
                            for t in _TECH.findall(row.get(col) or ''):
                                if t not in techs:
                                    techs.append(t)
                        if techs:
                            idx[cve] = techs
                _index = idx
    return _index


def ctid_coverage() -> int:
    """Nº de CVE con mapeo curado (para tests y documentación)."""
    return len(_load())


def heuristic_techniques(nvd: Dict[str, Any]) -> List[str]:
    """
    Regla a partir de las métricas CVSS que devuelve NVDClient. Sin datos de NVD -> [].
      * Red + sin privilegios + sin interacción del usuario -> T1190 Exploitation of Public-Facing Application
    Solo esa: las reglas para T1203 y T1068 no superaron la validación contra CTID (ver cabecera del módulo).
    """
    if not isinstance(nvd, dict) or not nvd.get('found'):
        return []
    av = str(nvd.get('attack_vector') or '').upper()
    ui = str(nvd.get('user_interaction') or '').upper()
    pr = str(nvd.get('privileges_required') or '').upper()
    needs_ui = ui in ('REQUIRED', 'ACTIVE', 'PASSIVE')
    if av in ('NETWORK', 'ADJACENT_NETWORK', 'ADJACENT') and pr in ('NONE', '') and not needs_ui:
        return ['T1190']
    return []


def cve_attack_techniques(cve_id: str, api_results: Dict[str, Any]) -> Dict[str, str]:
    """{técnica: procedencia} para el CVE. Vacío si no hay ni mapeo CTID ni datos CVSS."""
    curated = _load().get((cve_id or '').strip().upper())
    if curated:
        return {t: 'ctid' for t in curated}
    return {t: 'heuristic_cvss' for t in heuristic_techniques((api_results or {}).get('nvd'))}
