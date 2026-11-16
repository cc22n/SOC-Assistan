"""
Escape de texto NO CONFIABLE para los PDF de ReportLab.

`Paragraph(...)` interpreta su texto como marcado tipo HTML. Con datos controlables por un atacante
(salida del LLM influida por contenido externo, valores de IOC, títulos de sesión, nombres de técnicas)
eso permite:
  * <img src="http://host-interno/..."> -> ReportLab HACE la petición HTTP al renderizar: SSRF ciego
    (verificado con ReportLab 4.1.0 contra un servidor local) hacia la red interna o 169.254.169.254;
  * marcado roto -> OSError/ValueError -> la exportación da 500.
rl_config.trustedSchemes/trustedHosts NO lo impiden en 4.1.0 (verificado), así que la defensa es escapar.

Uso: Paragraph(f"<b>Análisis:</b> {esc(texto_del_llm)}", estilo)   # el marcado PROPIO (<b>) se queda
"""
from xml.sax.saxutils import escape


import re as _re

_CONTROL = _re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def plain(value) -> str:
    """Texto sin caracteres de control XML-ilegales (python-docx lanza ValueError con ellos -> 500)."""
    return _CONTROL.sub("", "" if value is None else str(value))


def esc(value) -> str:
    """Escapa &, < y > de cualquier valor (None -> ''). El resultado es texto literal para Paragraph."""
    if value is None:
        return ''
    return escape(str(value))
