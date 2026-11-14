"""
Regresión del lote rápido (full-audit-report.md, verificados abiertos el 2026-11-13):
  ALTO-09  XSS por interpolación sin escape en dashboard.html / analysis.html
  ALTO-17  pool SQLAlchemy sin timeouts
  ALTO-13  errores del LLM persistidos como resumen de sesión (contaminan chats futuros)
"""
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.services.session_manager import SessionManager, session_manager

ROOT = Path(__file__).resolve().parents[2]


def _tpl(name):
    return (ROOT / 'app' / 'templates' / name).read_text(encoding='utf-8')


class TestXssPlantillas:
    def test_dashboard_escapa_pais_y_conteo(self):
        html = _tpl('dashboard.html')
        assert '${escapeHtml(country)}' in html
        assert '${escapeHtml(stats.count)}' in html
        assert '<div class="font-semibold">${country}</div>' not in html

    def test_analysis_tabs_no_interpolan_en_onclick_js(self):
        html = _tpl('analysis.html')
        # el patrón vulnerable: nombre dentro de un string JS de un handler inline
        assert 'onclick=' not in html                       # ya no hay handlers inline (CSP)
        assert html.count('data-action="showTab"') == 2
        assert html.count("data-args='[${escapeHtml(JSON.stringify(s))}]'") == 2

    def test_escapehtml_cubre_comillas(self):
        base = _tpl('base.html')
        assert '&#39;' in base and '&quot;' in base and '&lt;' in base


class TestPoolConTimeouts:
    def test_opciones_de_engine(self, app):
        from app.config import Config
        opts = Config.SQLALCHEMY_ENGINE_OPTIONS
        assert opts['pool_timeout'] == 10
        assert opts['pool_size'] >= 1 and opts['max_overflow'] >= 0
        assert opts['connect_args']['connect_timeout'] == 5
        assert opts['pool_pre_ping'] is True

    def test_conexiones_maximas_caben_en_postgres(self):
        from app.config import Config
        o = Config.SQLALCHEMY_ENGINE_OPTIONS
        workers = 3                                   # --workers 3 en el Dockerfile
        assert workers * (o['pool_size'] + o['max_overflow']) < 100   # max_connections por defecto

    def test_el_engine_real_usa_el_pool_configurado(self, app):
        from app import db
        with app.app_context():
            pool = db.engine.pool
            assert pool.timeout() == 10 or getattr(pool, '_timeout', 10) == 10


class TestExtraerTextoDelResumen:
    @pytest.mark.parametrize('result', [
        {'error': 'groq API error: 429'},
        {'error': 'LLM service error: timeout'},
        {'error': ''}, {}, None, 123, ['lista'],
        {'analysis': ''}, {'analysis': 'corto'},
        'x' * 5,
    ])
    def test_respuestas_inservibles_devuelven_none(self, result):
        assert SessionManager._extract_summary_text(result) is None

    def test_error_con_texto_util_sigue_siendo_error(self):
        assert SessionManager._extract_summary_text(
            {'error': 'boom', 'analysis': 'a' * 50}) is None

    @pytest.mark.parametrize('result,esperado', [
        ({'analysis': 'Se analizó la IP 1.2.3.4 y se concluyó que es benigna.', 'raw_text': True},
         'Se analizó la IP 1.2.3.4 y se concluyó que es benigna.'),
        ({'content': '  Resumen de la conversación con varios IOCs.  '},
         'Resumen de la conversación con varios IOCs.'),
        ({'summary': 'Resumen en clave summary con suficiente longitud'},
         'Resumen en clave summary con suficiente longitud'),
        ('Texto plano devuelto directamente por el proveedor', 'Texto plano devuelto directamente por el proveedor'),
    ])
    def test_respuestas_validas(self, result, esperado):
        assert SessionManager._extract_summary_text(result) == esperado


class TestResumenDeSesionEndToEnd:
    def _sesion_con_mensajes(self, analyst_user, n=25):
        session, _ = session_manager.get_or_create_session(analyst_user.id)
        for i in range(n):
            session_manager.save_message(session.id, 'user' if i % 2 == 0 else 'assistant',
                                         f'mensaje {i} sobre la IP 8.8.8.8')
        return session

    def _generar(self, session_id, llm_result):
        llm = MagicMock(provider='deepseek')
        llm.generate.return_value = llm_result
        with patch.object(session_manager, '_get_llm_service', return_value=llm):
            session_manager._generate_compressed_summary(session_id)

    def test_error_de_api_no_se_guarda_como_resumen(self, app, db_session, analyst_user):
        with app.app_context():
            s = self._sesion_con_mensajes(analyst_user)
            self._generar(s.id, {'error': 'deepseek API error: 429'})
            db_session.session.refresh(s)
            assert s.compressed_summary is None
            assert s.summary_updated_at is None

    def test_error_no_pisa_un_resumen_bueno_anterior(self, app, db_session, analyst_user):
        with app.app_context():
            s = self._sesion_con_mensajes(analyst_user)
            s.compressed_summary = 'Resumen previo correcto de la investigación.'
            db_session.session.commit()
            self._generar(s.id, {'error': 'timeout'})
            db_session.session.refresh(s)
            assert s.compressed_summary == 'Resumen previo correcto de la investigación.'

    def test_resumen_valido_si_se_guarda(self, app, db_session, analyst_user):
        with app.app_context():
            s = self._sesion_con_mensajes(analyst_user)
            self._generar(s.id, {'analysis': 'Se investigó la IP 8.8.8.8: DNS público de Google, benigna.',
                                 'raw_text': True})
            db_session.session.refresh(s)
            assert s.compressed_summary.startswith('Se investigó la IP 8.8.8.8')
            assert s.summary_updated_at is not None
