"""
Tailwind COMPILADO (app/static/css/tailwind.css) en lugar del CDN `cdn.tailwindcss.com`.

El CDN generaba los estilos en el navegador: obligaba a `style-src 'unsafe-inline'` y a permitir en la CSP un
script de terceros sin versión fija. Con el CSS compilado la CSP puede exigir nonce en cada <style>.

Verificación hecha en Chrome real (17 páginas/estados, antes = CDN vs después = compilado): 0 reglas del CDN
ausentes en el compilado y 0 diferencias de estilo calculado en elementos estables.

Riesgo permanente: añadir una clase Tailwind en una plantilla y olvidar recompilar (`bash scripts/build_css.sh`).
`test_toda_clase_tailwind_de_las_plantillas_esta_compilada` lo detecta.
"""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CSS_PATH = ROOT / 'app' / 'static' / 'css' / 'tailwind.css'
TEMPLATES = sorted((ROOT / 'app' / 'templates').rglob('*.html'))

# Clases que aparecen en las plantillas pero NO tienen regla en ninguna versión (con el CDN tampoco la tenían):
# restos de Bootstrap (chat.html) y `prose` (plugin typography, que nunca estuvo cargado). Son inofensivas.
CLASES_SIN_REGLA = {'col-12', 'container-fluid', 'row', 'prose'}
# Prefijos que Jinja completa en ejecución (class="risk-{{ nivel }}"): las reglas están en <style> locales.
PREFIJOS_JINJA = ('alert-', 'risk-', 'toast-')


def _css():
    return CSS_PATH.read_text(encoding='utf-8')


def _css_escape(token):
    return re.sub(r'([^a-zA-Z0-9_\-])', lambda m: '\\' + m.group(1), token)


def _clases_locales():
    """Clases definidas en los bloques <style> de las plantillas (no son de Tailwind)."""
    out = set()
    for f in TEMPLATES:
        for blk in re.findall(r'<style[^>]*>(.*?)</style>', f.read_text(encoding='utf-8'), flags=re.S):
            out |= set(re.findall(r'\.([A-Za-z_][\w-]*)', blk))
    return out


class TestCssCompilado:
    def test_existe_y_es_razonable(self):
        assert CSS_PATH.is_file()
        n = CSS_PATH.stat().st_size
        assert 10_000 < n < 300_000, f'{n} bytes: ¿se generó vacío o se coló algo enorme?'

    def test_incluye_preflight_y_utilidades(self):
        css = _css()
        assert 'box-sizing:border-box' in css                   # preflight (reset base)
        assert '.hidden{display:none}' in css
        assert '.flex{display:flex}' in css

    def test_esta_minificado_y_sin_referencias_externas(self):
        css = _css()
        assert css.count('\n') < 5
        assert 'http://' not in css and 'https://' not in css.replace('https://tailwindcss.com', '')

    def test_la_version_de_tailwind_esta_fijada(self):
        sh = (ROOT / 'scripts' / 'build_css.sh').read_text(encoding='utf-8')
        assert 'TAILWIND_VERSION="3.4.17"' in sh                # la que servía el CDN: resultado visual idéntico
        assert 'npx --yes "tailwindcss@${TAILWIND_VERSION}"' in sh

    def test_script_de_build_tiene_sintaxis_valida(self):
        bash = shutil.which('bash')
        if not bash:
            pytest.skip('bash no disponible')
        r = subprocess.run([bash, '-n', 'scripts/build_css.sh'], capture_output=True, text=True, cwd=str(ROOT))
        if r.returncode != 0 and 'system32' in bash.lower():
            pytest.skip('bash de PATH es el lanzador de WSL; usa Git Bash')
        assert r.returncode == 0, r.stderr

    def test_config_escanea_las_plantillas(self):
        cfg = (ROOT / 'tailwind.config.js').read_text(encoding='utf-8')
        assert "content: ['./app/templates/**/*.html']" in cfg


class TestBaseUsaElCssCompilado:
    BASE = (ROOT / 'app' / 'templates' / 'base.html').read_text(encoding='utf-8')

    def test_enlaza_el_css_y_no_el_cdn(self):
        assert "url_for('static', filename='css/tailwind.css')" in self.BASE
        assert 'cdn.tailwindcss.com' not in self.BASE

    def test_el_enlace_va_el_ultimo_del_head(self):
        """El CDN inyectaba su <style> al FINAL del head: las utilidades ganan a los estilos locales en un empate."""
        head = self.BASE.split('</head>')[0]
        pos_css = head.index("filename='css/tailwind.css'")
        assert pos_css > head.index('{% block head %}')
        assert pos_css > head.index('<style')                    # tras el <style> local de base.html
        assert pos_css > head.index('font-awesome')

    def test_ninguna_plantilla_ni_modulo_referencia_el_cdn(self):
        for p in list((ROOT / 'app').rglob('*.py')) + TEMPLATES:
            assert 'cdn.tailwindcss.com' not in p.read_text(encoding='utf-8'), p.name

    def test_se_sirve_con_200(self, client):
        r = client.get('/static/css/tailwind.css')
        assert r.status_code == 200 and r.mimetype == 'text/css'


class TestNoSeOlvidaRecompilar:
    def test_toda_clase_tailwind_de_las_plantillas_esta_compilada(self):
        css = _css()
        locales = _clases_locales()
        faltan = {}
        for f in TEMPLATES:
            txt = re.sub(r'\{\{.*?\}\}|\{%.*?%\}', ' ', f.read_text(encoding='utf-8'), flags=re.S)
            for attr in re.findall(r'\sclass="([^"]*)"', txt):
                for tok in attr.split():
                    # fragmentos de expresiones JS/Jinja dentro del atributo, no clases reales
                    if re.search(r"""[${}'"|=?:]$|^[:=?|]|[${}'"]""", tok) and not re.fullmatch(r'[\w:\-/.\[\]%#!]+', tok):
                        continue
                    if not re.fullmatch(r'[a-z0-9][\w:\-/.\[\]%#!]*', tok) or tok.endswith('-'):
                        continue
                    if ('.' + _css_escape(tok)) in css:
                        continue
                    if tok in locales or tok in CLASES_SIN_REGLA or tok.startswith(PREFIJOS_JINJA):
                        continue
                    if tok.startswith('fa-') or tok in {'fa', 'fas', 'far', 'fab'}:
                        continue
                    faltan.setdefault(tok, set()).add(f.name)
        assert not faltan, (
            'clases de Tailwind usadas en plantillas pero ausentes del CSS compilado: '
            f'{ {k: sorted(v) for k, v in faltan.items()} }. Ejecuta: bash scripts/build_css.sh y commitea el CSS.')

    def test_el_detector_no_es_vacuo(self):
        """Control: una clase inexistente en el CSS SÍ se detecta como ausente."""
        assert ('.' + _css_escape('bg-teal-123456')) not in _css()
        assert ('.' + _css_escape('md:flex')) in _css()                      # y una real, con variante, SÍ está
        assert ('.' + _css_escape('hover:bg-gray-100')) in _css()
        assert ('.' + _css_escape('w-full')) in _css()
