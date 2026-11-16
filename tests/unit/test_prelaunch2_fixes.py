"""
Regresión de la 2ª auditoría pre-lanzamiento (2026-11-16). Los hallazgos se VERIFICARON antes de actuar
(la auditoría anterior de Gemini tuvo falsos positivos):
  * SSRF ciego vía ReportLab (hallazgo propio, NO estaba en el informe): <img src=...> en texto del LLM
  * MEDIO-01  ruta fantasma de exportación en analysis.html (+ DOCX individual inexistente)
  * MEDIO-02  backup_db.sh con `docker exec -t` (CRLF en la tubería)
  * MEDIO-03  el interceptor de fetch enviaba X-CSRFToken a cualquier origen
  * MEDIO-04  is_private_ip solo cubría RFC 1918 (no 169.254.169.254, CGNAT, multicast, IPv6)
  * hallazgo propio: history.html llamaba a /api/v2/analysis/<id> (404)
"""
import io
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.models.ioc import IOC, IOCAnalysis
from app.utils.pdf_safe import esc, plain
from app.utils.validators import extract_iocs_from_text, is_private_ip, validate_ioc

ROOT = Path(__file__).resolve().parents[2]


# ----------------------------------------------------------------------------- servidor "interno" local
@pytest.fixture
def interno():
    """Servidor HTTP local que registra cada visita: representa un host interno/metadatos cloud."""
    visitas = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            visitas.append(self.path)
            self.send_response(404)
            self.end_headers()

    srv = HTTPServer(('127.0.0.1', 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield SimpleNamespace(visitas=visitas, url=f'http://127.0.0.1:{srv.server_address[1]}',
                          payload=lambda: f'<img src="http://127.0.0.1:{srv.server_address[1]}/ssrf.png" width="5" height="5"/>')
    srv.shutdown()
    srv.server_close()


def _analisis_malicioso(db_session, user, payload):
    """Análisis cuyos campos controlables por un atacante (valor del IOC, salida del LLM, MITRE) llevan el payload."""
    ioc = IOC(value=f'evil-{payload}'[:200], ioc_type='domain')
    db_session.session.add(ioc)
    db_session.session.commit()
    a = IOCAnalysis(
        ioc_id=ioc.id, user_id=user.id, confidence_score=70, risk_level='ALTO',
        sources_used=['virustotal', payload], mitre_techniques=['T1071', payload],
        llm_analysis={'executive_summary': payload, 'key_findings': [payload, 'ok'],
                      'recommendations': [payload]},
    )
    db_session.session.add(a)
    db_session.session.commit()
    return a


# ============================================================================= SSRF vía ReportLab
class TestSsrfEnPdf:
    def test_CONTROL_sin_escapar_reportlab_SI_hace_la_peticion(self, interno):
        """Experimento de control: demuestra que el detector funciona y que la clase de bug es real."""
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate
        try:
            SimpleDocTemplate(io.BytesIO()).build([Paragraph(interno.payload(), getSampleStyleSheet()['Normal'])])
        except Exception:
            pass                                          # la imagen 404 hace fallar el build: da igual
        assert interno.visitas == ['/ssrf.png']

    def test_esc_neutraliza_el_payload(self, interno):
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate
        buf = io.BytesIO()
        SimpleDocTemplate(buf).build([Paragraph(esc(interno.payload()), getSampleStyleSheet()['Normal'])])
        assert buf.getvalue().startswith(b'%PDF') and interno.visitas == []

    @pytest.mark.parametrize('valor,esperado', [
        ('<b>x</b> & y', '&lt;b&gt;x&lt;/b&gt; &amp; y'), (None, ''), (5, '5'), ('', '')])
    def test_esc(self, valor, esperado):
        assert esc(valor) == esperado

    def test_plain_quita_caracteres_de_control_xml(self):
        assert plain('a\x00b\x08c\x1fd\te\nf') == 'abcd\te\nf'
        assert plain(None) == ''

    def test_pdf_de_un_analisis_no_provoca_peticiones(self, app, db_session, analyst_user, interno):
        from app.routes.report_routes import _generate_single_analysis_pdf
        with app.app_context():
            a = _analisis_malicioso(db_session, analyst_user, interno.payload())
            buf = _generate_single_analysis_pdf(a)
        assert buf is not None and buf.read(4) == b'%PDF'
        assert interno.visitas == []

    def test_pdf_de_una_sesion_no_provoca_peticiones(self, app, db_session, analyst_user, interno):
        from app.models.session import InvestigationSession
        from app.services.report_generator import report_generator
        from app.services.session_manager import session_manager
        with app.app_context():
            a = _analisis_malicioso(db_session, analyst_user, interno.payload())
            s = InvestigationSession(user_id=analyst_user.id, status='active', title=interno.payload())
            db_session.session.add(s)
            db_session.session.commit()
            session_manager.add_ioc_to_session(s.id, a.ioc_id, analysis_id=a.id)
            buf = report_generator.generate_pdf(s.id, include_api_details=True)
        assert buf is not None and buf.read(4) == b'%PDF'
        assert interno.visitas == []

    def test_las_rutas_devuelven_pdf_sin_peticiones(self, app, db_session, analyst_client, analyst_user, interno):
        with app.app_context():
            a = _analisis_malicioso(db_session, analyst_user, interno.payload())
            aid = a.id
        r = analyst_client.get(f'/api/v2/reports/analysis/{aid}/pdf')
        assert r.status_code == 200 and r.mimetype == 'application/pdf' and r.data[:4] == b'%PDF'
        assert interno.visitas == []

    def test_el_texto_se_conserva_literal_en_el_pdf(self, interno):
        """Escapar no pierde información: el analista sigue viendo el texto original (como texto)."""
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph
        p = Paragraph(esc('<img src="x"/> & más'), getSampleStyleSheet()['Normal'])
        assert p.getPlainText() == '<img src="x"/> & más'


# ============================================================================= MEDIO-01: DOCX + ruta
class TestExportacionDeAnalisis:
    @pytest.fixture
    def analisis(self, app, db_session, analyst_user):
        with app.app_context():
            ioc = IOC(value='198.51.100.9', ioc_type='ip')
            db_session.session.add(ioc)
            db_session.session.commit()
            a = IOCAnalysis(ioc_id=ioc.id, user_id=analyst_user.id, confidence_score=80, risk_level='ALTO',
                            sources_used=['virustotal'], mitre_techniques=['T1071'],
                            llm_analysis={'executive_summary': 'Resumen de prueba', 'key_findings': ['f1'],
                                          'recommendations': ['r1']})
            db_session.session.add(a)
            db_session.session.commit()
            return a.id

    def test_pdf_y_docx_del_dueno(self, analyst_client, analisis):
        pdf = analyst_client.get(f'/api/v2/reports/analysis/{analisis}/pdf')
        docx = analyst_client.get(f'/api/v2/reports/analysis/{analisis}/docx')
        assert pdf.status_code == 200 and pdf.data[:4] == b'%PDF'
        assert docx.status_code == 200 and docx.data[:2] == b'PK'
        assert docx.mimetype == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'

    def test_el_docx_contiene_el_analisis(self, analyst_client, analisis):
        from docx import Document
        d = Document(io.BytesIO(analyst_client.get(f'/api/v2/reports/analysis/{analisis}/docx').data))
        texto = '\n'.join(p.text for p in d.paragraphs) + '\n' + '\n'.join(
            c.text for t in d.tables for row in t.rows for c in row.cells)
        for esperado in ('198.51.100.9', 'ALTO', '80/100', 'Resumen de prueba', 'f1', 'r1', 'T1071', 'virustotal'):
            assert esperado in texto, esperado

    def test_docx_con_payload_y_caracteres_de_control_no_da_500(self, app, db_session, analyst_client,
                                                                 analyst_user, interno):
        with app.app_context():
            a = _analisis_malicioso(db_session, analyst_user, interno.payload() + '\x08\x1f')   # Postgres ya rechaza NUL
            aid = a.id
        r = analyst_client.get(f'/api/v2/reports/analysis/{aid}/docx')
        assert r.status_code == 200 and interno.visitas == []

    @pytest.mark.parametrize('fmt', ['pdf', 'docx'])
    def test_otro_analista_recibe_403_y_queda_auditado(self, app, other_client, analisis, fmt):
        from app.models.audit import AuditEvent
        r = other_client.get(f'/api/v2/reports/analysis/{analisis}/{fmt}')
        assert r.status_code == 403
        assert AuditEvent.query.filter_by(action='unauthorized_access', resource_type='analysis',
                                          resource_id=analisis).count() == 1

    @pytest.mark.parametrize('fmt', ['pdf', 'docx'])
    def test_admin_puede_exportar_cualquiera(self, admin_client, analisis, fmt):
        assert admin_client.get(f'/api/v2/reports/analysis/{analisis}/{fmt}').status_code == 200

    @pytest.mark.parametrize('fmt', ['pdf', 'docx'])
    def test_anonimo_y_inexistente(self, client, analyst_client, analisis, fmt):
        assert client.get(f'/api/v2/reports/analysis/{analisis}/{fmt}').status_code == 302
        assert analyst_client.get(f'/api/v2/reports/analysis/99999999/{fmt}').status_code == 404

    def test_la_plantilla_llama_a_las_rutas_reales(self):
        html = (ROOT / 'app' / 'templates' / 'analysis.html').read_text(encoding='utf-8')
        assert '/api/v2/reports/analysis/${currentAnalysisId}/${fmt}' in html
        assert 'single-analysis' not in html


class TestDetalleJsonDelAnalisis:
    """history.html llamaba a /api/v2/analysis/<id> y recibía 404."""

    @pytest.fixture
    def aid(self, app, db_session, analyst_user, sample_ioc):
        with app.app_context():
            a = IOCAnalysis(ioc_id=sample_ioc.id, user_id=analyst_user.id, confidence_score=82,
                            risk_level='ALTO', recommendation='Bloquear',
                            virustotal_data={'malicious': 47})
            db_session.session.add(a)
            db_session.session.commit()
            return a.id

    def test_dueno(self, analyst_client, aid):
        r = analyst_client.get(f'/api/v2/analysis/{aid}')
        body = r.get_json()
        assert r.status_code == 200 and body['success'] is True
        assert body['ioc_value'] == '185.220.101.34' and body['risk_level'] == 'ALTO'
        assert body['recommendation'] == 'Bloquear'
        assert 'virustotal' not in body                  # sin datos crudos de APIs

    def test_ajeno_403(self, other_client, aid):
        assert other_client.get(f'/api/v2/analysis/{aid}').status_code == 403

    def test_admin_200(self, admin_client, aid):
        assert admin_client.get(f'/api/v2/analysis/{aid}').status_code == 200

    def test_inexistente_404(self, analyst_client):
        assert analyst_client.get('/api/v2/analysis/99999999').status_code == 404

    def test_anonimo_302(self, client, aid):
        assert client.get(f'/api/v2/analysis/{aid}').status_code == 302


class TestPlantillasLlamanARutasReales:
    """Habría detectado MEDIO-01 y el 404 de history.html: toda URL fetch('/...') de las plantillas debe existir."""

    def test_toda_url_de_fetch_tiene_ruta_y_metodo(self, app):
        rules = []
        for r in app.url_map.iter_rules():
            rules.append((re.compile('^' + re.sub(r'<[^>]*>', '[^/]+', re.escape(r.rule)) + '/?$'),
                          r.methods - {'HEAD', 'OPTIONS'}))
        url_re = re.compile(r"""fetch\(\s*[`'"](/[^`'"?]*)""")
        fallos = []
        total = 0
        for f in (ROOT / 'app' / 'templates').rglob('*.html'):
            txt = f.read_text(encoding='utf-8')
            for m in url_re.finditer(txt):
                total += 1
                u = re.sub(r'\$\{[^}]*\}', 'X', m.group(1)).rstrip('/')
                mm = re.search(r"method:\s*['\"](\w+)['\"]", txt[m.start(): m.start() + 260])
                method = mm.group(1).upper() if mm else 'GET'
                # ${fmt} dinámico en el último segmento: se acepta si existe con algún formato conocido
                candidatos = [u] + [u[:-1] + fmt for fmt in ('pdf', 'docx', 'json')] if u.endswith('/X') else [u]
                if not any(rx.match(c) and method in ms for c in candidatos for rx, ms in rules):
                    fallos.append(f'{f.name}: {method} {m.group(1)}')
        assert total >= 15, 'la regex dejó de encontrar llamadas'
        assert not fallos, f'plantillas que llaman a rutas inexistentes: {fallos}'


# ============================================================================= MEDIO-02: backup
class TestBackup:
    SCRIPT = (ROOT / 'scripts' / 'ops' / 'backup_db.sh').read_text(encoding='utf-8')

    def test_pg_dump_sin_pseudo_tty(self):
        """`docker exec -t` convierte \\n en \\r\\n en la tubería (verificado con od -c)."""
        linea = next(l for l in self.SCRIPT.splitlines() if 'docker exec' in l and 'pg_dump' in l)
        assert re.search(r'docker exec -i\b', linea)
        assert not re.search(r'docker exec\s+(-\w*t\w*|--tty)\b', linea)

    def test_ningun_script_de_ops_usa_exec_con_tty(self):
        for sh in (ROOT / 'scripts' / 'ops').glob('*.sh'):
            for n, linea in enumerate(sh.read_text(encoding='utf-8').splitlines(), 1):
                if linea.lstrip().startswith('#'):
                    continue
                assert not re.search(r'docker (compose )?exec\s+(-\w*t\w*|--tty)\b', linea), f'{sh.name}:{n}'


# ============================================================================= MEDIO-03: CSRF mismo origen
class TestInterceptorCsrf:
    BASE = (ROOT / 'app' / 'templates' / 'base.html').read_text(encoding='utf-8')

    def test_existe_isSameOrigin_y_condiciona_el_token(self):
        assert 'function isSameOrigin(url)' in self.BASE
        assert re.search(r"if \(token && isSameOrigin\(url\) && options\.method", self.BASE)

    def test_resuelve_urls_relativas_y_objetos_request(self):
        assert 'new URL(target, window.location.href).origin === window.location.origin' in self.BASE
        assert 'url instanceof Request' in self.BASE


# ============================================================================= MEDIO-04: IPs reservadas
class TestIpsNoEnrutables:
    @pytest.mark.parametrize('ip', [
        '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '127.0.0.1', '127.255.255.254',
        '169.254.169.254', '169.254.0.1',                                    # metadatos cloud / link-local
        '0.0.0.0', '100.64.0.1', '100.127.255.255', '224.0.0.1', '239.255.255.255', '240.0.0.1', '255.255.255.255',
        '::1', 'fe80::1', 'fc00::1', 'fd12:3456::1', '::', 'ff02::1', '::ffff:10.0.0.1', '::ffff:169.254.169.254',
    ])
    def test_privadas_o_reservadas(self, ip):
        assert is_private_ip(ip) is True

    @pytest.mark.parametrize('ip', [
        '8.8.8.8', '1.1.1.1', '185.220.101.34', '172.15.255.255', '172.32.0.1', '100.63.255.255', '100.128.0.1',
        '169.253.0.1', '169.255.0.1', '11.0.0.1', '2001:4860:4860::8888', '::ffff:8.8.8.8',
        '203.0.113.50', '198.51.100.5', '192.0.2.1',                         # documentación: válidas como ejemplo
    ])
    def test_publicas(self, ip):
        assert is_private_ip(ip) is False

    @pytest.mark.parametrize('ip', ['', 'abc', '999.1.1.1', '1.2.3', None, '1.2.3.4.5', '10.0.0'])
    def test_entradas_invalidas_no_lanzan(self, ip):
        assert is_private_ip(ip) is False

    def test_validate_ioc_rechaza_metadatos_cloud(self):
        ok, msg = validate_ioc('169.254.169.254', 'ip')
        assert ok is False and 'Private/reserved' in msg

    def test_extract_iocs_ignora_ips_no_enrutables(self):
        found = extract_iocs_from_text('conecta a 169.254.169.254, 100.64.0.9, 10.0.0.1 y 8.8.8.8')
        valores = json.dumps(found, default=str)
        assert '8.8.8.8' in valores
        for no in ('169.254.169.254', '100.64.0.9', '10.0.0.1'):
            assert no not in valores
