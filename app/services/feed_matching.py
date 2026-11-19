"""
Casado de un CVE contra el stack declarado (WP6 de PLAN-FUSION). Funciones puras, sin BD.

Un CVE trae una lista de pares (vendor, product) afectados: en KEV vienen estructurados (`vendorProject`/`product`) y en los
CVE recién publicados de NVD vienen en `affected[].affectedData[]` de la CNA (el 100 % de los 204 CVE graves de las últimas
48 h los traía, aunque NVD aún no tuviera CPE; verificado en vivo el 2026-11-19).

Reglas (deliberadamente simples y predecibles; un analista debe poder anticipar si algo va a casar):
  * Se normaliza a minúsculas y a tokens alfanuméricos, descartando palabras de forma jurídica ("Corporation", "Inc"...).
  * Una entrada del stack tiene vendor y/o producto. Casa con un par afectado si TODOS los tokens de cada campo declarado
    aparecen entre los tokens del campo correspondiente. Un campo no declarado no restringe.
  * Un token casa si es IGUAL, o si el del CVE es el de la entrada más dígitos de versión ('log4j' casa 'log4j2').
    Nunca por subcadena: 'go' NO casa 'google'.

Límites conocidos (documentados en scripts/baseline/README.md): una entrada solo de producto ('ios') casa productos de varios
vendors (Cisco IOS y Apple iOS): declarar también el vendor lo evita. No se casa por el texto de la descripción.
"""
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence

_STOP = frozenset({
    'inc', 'corp', 'corporation', 'ltd', 'limited', 'llc', 'co', 'company', 'the', 'foundation', 'project', 'software',
    'systems', 'group', 'gmbh', 'ag', 'sa', 'technologies', 'technology',
})
_NON_INFORMATIVE = frozenset({'n/a', 'na', 'unknown', '-', 'not applicable', 'none', ''})


def tokens(text: Optional[str]) -> List[str]:
    """Tokens significativos de un nombre de vendor o producto."""
    if not text or text.strip().lower() in _NON_INFORMATIVE:
        return []
    return [t for t in re.findall(r'[a-z0-9]+', text.lower()) if t not in _STOP]


def _token_matches(wanted: str, candidate: str) -> bool:
    return candidate == wanted or re.fullmatch(re.escape(wanted) + r'\d+', candidate) is not None


def _field_matches(wanted_text: Optional[str], candidate_text: Optional[str]) -> bool:
    wanted = tokens(wanted_text)
    if not wanted:                        # campo no declarado -> no restringe
        return True
    cand = tokens(candidate_text)
    return bool(cand) and all(any(_token_matches(w, c) for c in cand) for w in wanted)


def entry_is_valid(vendor: Optional[str], product: Optional[str]) -> bool:
    """Una entrada necesita al menos un token informativo (si no, casaría con todo)."""
    return bool(tokens(vendor) or tokens(product))


def entry_matches(vendor: Optional[str], product: Optional[str], affected: Iterable[Dict[str, Any]]) -> bool:
    if not entry_is_valid(vendor, product):
        return False
    for pair in affected or []:
        if _field_matches(vendor, pair.get('vendor')) and _field_matches(product, pair.get('product')):
            return True
    return False


def match_entries(entries: Sequence[Any], affected: Iterable[Dict[str, Any]]) -> List[int]:
    """Ids de las entradas del stack (objetos con .id/.vendor/.product) que casan con la lista de afectados."""
    affected = list(affected or [])
    return [e.id for e in entries if entry_matches(e.vendor, e.product, affected)]
