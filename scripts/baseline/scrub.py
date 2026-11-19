"""
Redactado de datos de terceros en los snapshots de la línea base ANTES de guardarlos (auditoría del 2026-11-19).

Los snapshots son respuestas reales de urlscan/VirusTotal/etc. sobre páginas de phishing y sitios reales, y arrastran datos que
no deben vivir en un repositorio: direcciones de correo de PERSONAS (apareció una de un banco en el HTML de una página de
phishing), claves de API de terceros incrustadas en esas páginas (`AIza...`), códigos de restablecimiento de contraseña
(`oobCode`) y valores de cabeceras `set-cookie`. Nada de eso lo necesita el scoring, que solo lee verdictos y contadores.

Uso:  python scripts/baseline/scrub.py archivo.json [...]     (idempotente; reescribe el archivo)
Lo llama `collect.py` antes de escribir un snapshot nuevo.
"""
import re
import sys
from pathlib import Path

_EMAIL = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')
_AIZA = re.compile(r'AIza[0-9A-Za-z_\-]{35}')
_OOB = re.compile(r'(oobCode=)[^&"\s\\]+')
_COOKIE = re.compile(r'("set-cookie"\s*:\s*")[^"]*(")', re.IGNORECASE)

PLACEHOLDER_EMAIL = 'redacted@example.invalid'


def scrub_text(text: str) -> str:
    text = _EMAIL.sub(PLACEHOLDER_EMAIL, text)
    text = _AIZA.sub('AIza_REDACTED', text)
    text = _OOB.sub(r'\1REDACTED', text)
    text = _COOKIE.sub(r'\1REDACTED\2', text)
    return text


def main(paths):
    for p in map(Path, paths):
        original = p.read_text(encoding='utf-8')
        clean = scrub_text(original)
        if clean != original:
            p.write_text(clean, encoding='utf-8')
        print(f'{p.name}: {"redactado" if clean != original else "sin cambios"}')


if __name__ == '__main__':
    main(sys.argv[1:])
