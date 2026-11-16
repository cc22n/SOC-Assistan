"""
Regresión de ALTO-11 (CSP estricta con nonce).

Verificado ademas en navegador real (Chrome) con un XSS simulado: se bloquean script inline
sin nonce, script externo sin nonce, handlers inline, URLs javascript: y eval; los scripts con
nonce y los que estos crean (strict-dynamic) siguen funcionando.
"""
import re
from pathlib import Path

import pytest

from app import build_csp

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = sorted((ROOT / 'app' / 'templates').rglob('*.html'))


def _csp(resp):
    return resp.headers['Content-Security-Policy']


def _directive(csp, name):
    for part in csp.split(';'):
        part = part.strip()
        if part.startswith(name + ' ') or part == name:
            return part
    return None


class TestCabeceraCsp:
    def test_script_src_estricto(self, client):
        csp = _csp(client.get('/auth/login'))
        script = _directive(csp, 'script-src')
        assert "'unsafe-inline'" not in script
        assert "'unsafe-eval'" not in script
        assert "'strict-dynamic'" in script
        assert re.search(r"'nonce-[A-Za-z0-9_-]{16,}'", script)

    def test_directivas_de_endurecimiento(self, client):
        csp = _csp(client.get('/auth/login'))
        assert _directive(csp, 'script-src-attr') == "script-src-attr 'none'"
        assert _directive(csp, 'object-src') == "object-src 'none'"
        assert _directive(csp, 'base-uri') == "base-uri 'self'"
        assert _directive(csp, 'form-action') == "form-action 'self'"
        assert _directive(csp, 'frame-ancestors') == "frame-ancestors 'none'"
        assert _directive(csp, 'default-src') == "default-src 'self'"

    def test_nonce_distinto_en_cada_peticion(self, client):
        n = set()
        for _ in range(5):
            m = re.search(r"'nonce-([^']+)'", _csp(client.get('/auth/login')))
            n.add(m.group(1))
        assert len(n) == 5

    def test_el_nonce_del_header_es_el_de_los_script_del_html(self, client):
        r = client.get('/auth/register')
        nonce = re.search(r"'nonce-([^']+)'", _csp(r)).group(1)
        html = r.get_data(as_text=True)
        tags = re.findall(r'<script\b[^>]*>', html)
        assert tags, 'la pagina deberia tener al menos un <script>'
        for t in tags:
            assert f'nonce="{nonce}"' in t, t

    def test_paginas_autenticadas_tambien_llevan_nonce(self, analyst_client):
        for path in ('/dashboard', '/chat', '/history', '/incidents', '/analyze', '/api-health'):
            r = analyst_client.get(path)
            assert r.status_code == 200, path
            nonce = re.search(r"'nonce-([^']+)'", _csp(r)).group(1)
            for t in re.findall(r'<script\b[^>]*>', r.get_data(as_text=True)):
                assert f'nonce="{nonce}"' in t, (path, t)

    def test_respuestas_de_error_tambien_llevan_csp(self, client):
        r = client.get('/ruta-que-no-existe')
        assert r.status_code == 404
        assert "'nonce-" in _csp(r)

    def test_fuentes_de_google_permitidas_en_estilos(self, client):
        assert 'https://fonts.googleapis.com' in _directive(_csp(client.get('/auth/login')), 'style-src')


class TestBuildCsp:
    def test_upgrade_insecure_solo_si_se_pide(self):
        assert 'upgrade-insecure-requests' not in build_csp('abc')
        assert 'upgrade-insecure-requests' in build_csp('abc', upgrade_insecure=True)

    def test_incluye_el_nonce_dado(self):
        assert "'nonce-XYZ'" in build_csp('XYZ')


class TestPlantillasCompatiblesConCsp:
    @pytest.mark.parametrize('path', TEMPLATES, ids=lambda p: str(p.relative_to(ROOT / 'app' / 'templates')))
    def test_todo_script_lleva_nonce(self, path):
        for tag in re.findall(r'<script\b[^>]*>', path.read_text(encoding='utf-8')):
            assert 'nonce="{{ csp_nonce() }}"' in tag, f'{path.name}: {tag}'

    @pytest.mark.parametrize('path', TEMPLATES, ids=lambda p: str(p.relative_to(ROOT / 'app' / 'templates')))
    def test_sin_handlers_inline(self, path):
        html = path.read_text(encoding='utf-8')
        bad = re.findall(r"""[\s"'`]on(?:click|change|input|submit|keydown|keyup|keypress|load|error|"""
                         r"""mouseover|mouseout|focus|blur|dblclick|toggle)\s*=""", html, flags=re.I)
        assert not bad, f'{path.name} tiene handlers inline: {bad}'
        assert 'javascript:' not in html.lower(), f'{path.name} usa una URL javascript:'

    def test_cada_accion_apunta_a_una_funcion_que_existe(self):
        """Habria detectado el boton muerto exportAnalysis() de history.html."""
        names = {}
        for path in TEMPLATES:
            html = path.read_text(encoding='utf-8')
            for m in re.finditer(r'data-(?:action|change|input|enter)="([A-Za-z_$][\w$]*)"', html):
                names.setdefault(m.group(1), set()).add(path.name)
        assert names, 'no se encontraron acciones: la regex o las plantillas cambiaron'
        corpus = {p.name: p.read_text(encoding='utf-8') for p in TEMPLATES}
        faltan = []
        for name, files in names.items():
            definido = any(
                re.search(rf'(?:function\s+{re.escape(name)}\b|window\.{re.escape(name)}\s*=)', corpus[f])
                for f in files)
            if not definido:
                faltan.append((name, sorted(files)))
        assert not faltan, f'acciones sin funcion definida en su plantilla: {faltan}'

    def test_ui_actions_no_evalua_texto(self):
        js = (ROOT / 'app' / 'static' / 'ui-actions.js').read_text(encoding='utf-8')
        code = re.sub(r'/\*.*?\*/', '', js, flags=re.S)           # ignora comentarios
        code = re.sub(r'//[^\n]*', '', code)
        for prohibido in ('eval(', 'new Function', 'setTimeout("', "setTimeout('", 'innerHTML', 'document.write'):
            assert prohibido not in code, prohibido

    def test_base_carga_ui_actions_con_nonce(self):
        base = (ROOT / 'app' / 'templates' / 'base.html').read_text(encoding='utf-8')
        assert re.search(r'<script nonce="\{\{ csp_nonce\(\) \}\}" src="\{\{ url_for\(\'static\', filename=\'ui-actions\.js\'\) \}\}">', base)

    def test_register_standalone_tambien_la_carga(self):
        reg = (ROOT / 'app' / 'templates' / 'auth' / 'register.html').read_text(encoding='utf-8')
        assert 'ui-actions.js' in reg


class TestServidorSirveUiActions:
    def test_static_ui_actions(self, client):
        r = client.get('/static/ui-actions.js')
        assert r.status_code == 200
        assert b'data-action' in r.data


class TestEstilosConNonce:
    """Tailwind compilado + nonce en <style>: sin 'unsafe-inline' en style-src/style-src-elem (verificado en Chrome:
    un <style> inyectado, su @import y una hoja de evil.example quedan bloqueados; el <style> con nonce funciona)."""

    def test_style_src_sin_unsafe_inline_y_con_nonce(self, client):
        csp = _csp(client.get('/auth/login'))
        for nombre in ('style-src', 'style-src-elem'):
            d = _directive(csp, nombre)
            assert "'unsafe-inline'" not in d, d
            assert re.search(r"'nonce-[A-Za-z0-9_-]{16,}'", d), d

    def test_residual_deliberado_solo_en_atributos(self, client):
        """Los style="..." no se pueden proteger con nonce: unica excepcion, y solo para ATRIBUTOS."""
        assert _directive(_csp(client.get('/auth/login')), 'style-src-attr') == "style-src-attr 'unsafe-inline'"

    def test_ya_no_se_permite_tailwind_ni_jsdelivr_en_estilos(self, client):
        csp = _csp(client.get('/auth/login'))
        assert 'tailwindcss' not in csp
        assert 'jsdelivr' not in _directive(csp, 'style-src')
        assert 'jsdelivr' not in _directive(csp, 'style-src-elem')

    def test_el_mismo_nonce_en_script_style_y_html(self, client):
        r = client.get('/auth/register')
        csp = _csp(r)
        nonces = set(re.findall(r"'nonce-([^']+)'", csp))
        assert len(nonces) == 1                                  # un único nonce por respuesta
        html = r.get_data(as_text=True)
        n = re.search(r"'nonce-([^']+)'", csp).group(1)
        estilos = re.findall(r'<style\b[^>]*>', html)
        assert estilos and all(f'nonce="{n}"' in t for t in estilos), estilos

    @pytest.mark.parametrize('path', ['/dashboard', '/chat', '/analyze', '/history', '/incidents', '/api-health'])
    def test_paginas_autenticadas_estilos_con_el_nonce_de_la_respuesta(self, analyst_client, path):
        r = analyst_client.get(path)
        n = re.search(r"'nonce-([^']+)'", _csp(r)).group(1)
        for tag in re.findall(r'<style\b[^>]*>', r.get_data(as_text=True)):
            assert f'nonce="{n}"' in tag, (path, tag)

    def test_el_html_enlaza_el_css_compilado_y_no_el_cdn(self, analyst_client):
        html = analyst_client.get('/dashboard').get_data(as_text=True)
        assert '/static/css/tailwind.css' in html and 'cdn.tailwindcss.com' not in html

    @pytest.mark.parametrize('path', TEMPLATES, ids=lambda p: str(p.relative_to(ROOT / 'app' / 'templates')))
    def test_todo_style_de_las_plantillas_lleva_nonce(self, path):
        for tag in re.findall(r'<style\b[^>]*>', path.read_text(encoding='utf-8')):
            assert 'nonce="{{ csp_nonce() }}"' in tag, f'{path.name}: {tag}'


class TestIntegridadDeRecursosDeCdn:
    """SRI en todo recurso de terceros que se ejecuta/aplica: un CDN comprometido ya no puede servir código distinto."""

    # hashes verificados contra DOS fuentes independientes (API del CDN y cálculo propio sobre el archivo)
    ESPERADOS = {
        'https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.js':
            'sha256-dEAdc43T4D7l37O2hBIQ/ixOrYqWDEARykugt4qf2PM=',
        'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js':
            'sha512-puJW3E/qXDqYp9IfhAI54BJEaWIfloJ7JWs7OeD5i6ruC9JZL1gERT1wjtwXFlh7CjE7ZJ+/vcRZRkIYIb6p4g==',
        'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css':
            'sha512-h9FcoyWjHcOcmEVkxOfTLnmZFWIH0iZhZT1H2TbOq55xssQGEJHEaIm+PgoUaZbRvQTNTluNOEfb1ZRy6D3BOw==',
        'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css':
            'sha512-iecdLmaskl7CVkqkXNQ/ZH/XLlvWZOJyj7Yy7tcenmpD1ypASozpmT/E0iPtmFIB46ZmdtAc9eNBvH0H/ZpiBw==',
    }

    @staticmethod
    def _externos():
        """(archivo, url, etiqueta) de cada <script src> / <link stylesheet> hacia https://."""
        out = []
        for f in TEMPLATES:
            txt = f.read_text(encoding='utf-8')
            for tag in re.findall(r'<(?:script|link)\b[^>]*>', txt):
                m = re.search(r'(?:src|href)="(https?://[^"]+)"', tag)
                if m and 'stylesheet' in tag or (m and tag.startswith('<script')):
                    out.append((f.name, m.group(1), tag))
        return out

    def test_se_encuentran_los_recursos_de_cdn(self):
        urls = {u for _, u, _ in self._externos()}
        assert set(self.ESPERADOS) <= urls, urls

    def test_todo_recurso_externo_tiene_integrity_y_crossorigin(self):
        for archivo, url, tag in self._externos():
            assert re.search(r'integrity="(sha256|sha384|sha512)-[A-Za-z0-9+/=]+"', tag), f'{archivo}: {url} sin SRI'
            assert 'crossorigin="anonymous"' in tag, f'{archivo}: {url} sin crossorigin'

    def test_los_hashes_coinciden_con_los_verificados(self):
        for archivo, url, tag in self._externos():
            assert f'integrity="{self.ESPERADOS[url]}"' in tag, f'{archivo}: hash distinto al verificado para {url}'

    def test_chart_js_usa_el_archivo_publicado_no_el_minificado_al_vuelo(self):
        """jsDelivr GENERA *.min.js minificando al vuelo: su hash puede cambiar si cambian su minificador."""
        for _, url, _ in self._externos():
            if 'chart.js' in url:
                assert url.endswith('/dist/chart.umd.js') and '.min.' not in url
