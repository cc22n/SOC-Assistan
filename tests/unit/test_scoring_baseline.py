"""
Scoring del análisis contra respuestas REALES de 85 IOCs (scripts/baseline, 2026-11-18) y su regla de cobertura.

Antecedente: el score sumaba +5 por cada API que respondía sin error aunque dijera "limpio"; en benignos el 98 %
del score era eso (google.com salía MEDIO). Cada garantía lleva su control: el scoring ANTIGUO, reproducido aquí,
debe incumplirla; si no, el test no demuestra nada.
"""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from app.models.ioc import IOCAnalysis
from app.services.llm_orchestrator import LLMOrchestrator

ROOT = Path(__file__).resolve().parents[2]
SNAPS = json.loads((ROOT / 'tests/fixtures/baseline/snapshots.json').read_text(encoding='utf-8'))
DATASET = json.loads((ROOT / 'scripts/baseline/dataset.json').read_text(encoding='utf-8'))

ORCH = LLMOrchestrator.__new__(LLMOrchestrator)        # solo se usan métodos puros del scoring


def _score(row):
    return ORCH._calculate_enhanced_score(SNAPS[f"{row['type']}:{row['value']}"]['api_results'], {})


def _old_score(row):
    """Scoring ANTERIOR, reproducido fielmente: +5 por API sin error y VirusTotal = min(30, 2 * malicious)."""
    res = SNAPS[f"{row['type']}:{row['value']}"]['api_results']
    nuevo = ORCH._calculate_enhanced_score(res, {})
    vt = res.get('virustotal')
    if vt and 'error' not in vt:
        det = vt.get('malicious', vt.get('positive_detections', 0)) or 0
        nuevo += (min(30, det * 2) if det > 0 else 0) - ORCH._virustotal_points(vt)
    return min(100, nuevo + 5 * sum(1 for r in res.values() if 'error' not in r))


def _auc(scores_mal, scores_ben):
    w = sum(1 if m > b else 0.5 if m == b else 0 for m in scores_mal for b in scores_ben)
    return w / (len(scores_mal) * len(scores_ben))


def _rows(label, tipo=None):
    return [r for r in DATASET if r['label'] == label and (tipo is None or r['type'] == tipo)]


class TestFixtureIntegridad:
    def test_dataset_y_respuestas_coinciden(self):
        faltan = [r['value'] for r in DATASET if f"{r['type']}:{r['value']}" not in SNAPS]
        assert not faltan and len(DATASET) == 85

    def test_hay_respuestas_reales_no_inventadas(self):
        """Las respuestas congeladas traen los campos que consume el scoring (no formas inventadas)."""
        vt = [s['api_results']['virustotal'] for s in SNAPS.values()
              if 'virustotal' in s['api_results'] and 'error' not in s['api_results']['virustotal']]
        assert len(vt) > 30 and all('malicious' in v for v in vt)


class TestSinPuntosDePresencia:
    def test_ningun_benigno_llega_a_medio(self):
        sobre = [(r['value'], _score(r)) for r in _rows('benign') if _score(r) >= 30]
        assert sobre == []

    def test_control_el_scoring_antiguo_si_marcaba_benignos(self):
        """Sin este control el test anterior podría pasar con cualquier scoring."""
        sobre = [r for r in _rows('benign') if _old_score(r) >= 30]
        assert len(sobre) >= 8

    def test_api_que_responde_limpio_aporta_cero(self):
        res = {f'api{i}': {'found': False} for i in range(8)}
        assert ORCH._calculate_enhanced_score(res, {}) == 0

    def test_la_presencia_ya_no_decide_el_nivel(self):
        """Un dominio con 7 APIs respondiendo limpio es LIMPIO (antes 35 = MEDIO)."""
        google = next(r for r in _rows('benign', 'domain') if r['value'] == 'google.com')
        assert ORCH._determine_risk_level(_score(google)) == 'LIMPIO'
        assert ORCH._determine_risk_level(_old_score(google)) == 'MEDIO'


class TestDiscriminacion:
    """AUC = prob. de que un malicioso puntúe más que un benigno (no depende del umbral)."""

    @pytest.mark.parametrize('tipo,minimo', [('domain', 0.90), ('url', 0.95), ('hash', 0.95)])
    def test_auc_por_tipo(self, tipo, minimo):
        auc = _auc([_score(r) for r in _rows('malicious', tipo)], [_score(r) for r in _rows('benign', tipo)])
        assert auc >= minimo, f'{tipo}: AUC {auc:.2f} < {minimo}'

    def test_auc_global_no_empeora_respecto_al_antiguo(self):
        mal, ben = _rows('malicious'), _rows('benign')
        nuevo = _auc([_score(r) for r in mal], [_score(r) for r in ben])
        viejo = _auc([_old_score(r) for r in mal], [_old_score(r) for r in ben])
        assert nuevo >= viejo

    def test_control_dominios_antes_no_discriminaban(self):
        auc_viejo = _auc([_old_score(r) for r in _rows('malicious', 'domain')],
                         [_old_score(r) for r in _rows('benign', 'domain')])
        assert auc_viejo < 0.80, auc_viejo


class TestVirusTotal:
    @pytest.mark.parametrize('vt,esperado', [
        ({}, 0), ({'malicious': 0}, 0), ({'malicious': 1}, 10), ({'malicious': 2}, 13), ({'malicious': 3}, 16),
        ({'malicious': 100}, 40),                                       # tope
        ({'suspicious': 1}, 2), ({'suspicious': 50}, 10),               # tope
        ({'reputation': -11}, 10), ({'reputation': 0}, 0), ({'reputation': 700}, 0),
        ({'reputation': 'n/a'}, 0), ({'reputation': None}, 0),
        ({'malicious': 4, 'suspicious': 2, 'reputation': -11}, 19 + 4 + 10),
        ({'positive_detections': 3}, 16),                               # clave antigua
    ])
    def test_bandas(self, vt, esperado):
        assert ORCH._virustotal_points(vt) == esperado

    def test_vt_con_error_no_puntua(self):
        assert ORCH._calculate_enhanced_score({'virustotal': {'error': 'HTTP 429', 'malicious': 99}}, {}) == 0


class TestCobertura:
    def test_todo_ok(self):
        c = ORCH._api_coverage({'a': {'x': 1}, 'b': {'found': False}})
        assert c == {'ok': 2, 'failed': [], 'total': 2, 'incomplete': False}

    def test_fallo_no_es_limpio(self):
        c = ORCH._api_coverage({'a': {'found': False}, 'b': {'error': 'HTTP 403'}, 'c': {'error': 'Timeout'}})
        assert c['ok'] == 1 and c['failed'] == ['b', 'c'] and c['incomplete'] is True

    def test_respuesta_no_dict_cuenta_como_fallo(self):
        assert ORCH._api_coverage({'a': None})['failed'] == ['a']

    def test_vacio(self):
        assert ORCH._api_coverage({}) == {'ok': 0, 'failed': [], 'total': 0, 'incomplete': False}


class TestRutaSinEvidencia:
    BASE = '/api/v2'
    RES = {'confidence_score': 0, 'risk_level': 'LIMPIO', 'llm_analysis': {}, 'mitre_techniques': [],
           'processing_time': 0.1, 'sources_used': ['abuseipdb'], 'timestamp': '2026-11-18T00:00:00+00:00'}

    def _post(self, client, res):
        with patch('app.routes.api_v2_routes.get_orchestrator') as o, \
                patch('app.services.ioc_cache.get_cached_analysis', return_value=None):
            o.return_value.analyze_with_intelligence.return_value = res
            return client.post(f'{self.BASE}/analyze/enhanced', json={
                'ioc': '203.0.113.7', 'type': 'ip', 'use_llm_planning': False})

    def test_ninguna_fuente_responde_devuelve_502_y_no_guarda(self, app, db_session, analyst_client):
        antes = IOCAnalysis.query.count()
        res = {**self.RES, 'api_results': {'abuseipdb': {'error': 'HTTP 500'}},
               'api_coverage': {'ok': 0, 'failed': ['abuseipdb'], 'total': 1, 'incomplete': True}}
        r = self._post(analyst_client, res)
        assert r.status_code == 502
        assert r.get_json()['api_coverage']['ok'] == 0
        assert IOCAnalysis.query.count() == antes

    def test_control_con_una_fuente_ok_si_guarda_y_expone_cobertura(self, app, db_session, analyst_client):
        antes = IOCAnalysis.query.count()
        res = {**self.RES, 'api_results': {'abuseipdb': {'abuse_confidence_score': 0}, 'shodan': {'error': 'x'}},
               'api_coverage': {'ok': 1, 'failed': ['shodan'], 'total': 2, 'incomplete': True}}
        r = self._post(analyst_client, res)
        assert r.status_code == 200
        assert r.get_json()['api_coverage']['failed'] == ['shodan']
        assert IOCAnalysis.query.count() == antes + 1
