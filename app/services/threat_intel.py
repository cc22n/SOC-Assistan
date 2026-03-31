"""
Servicio de Threat Intelligence - Orquesta todos los análisis
ACTUALIZADO: Usa new_api_clients.py con las 17 APIs y MITRE dinámico

CAMBIOS:
- Importa de new_api_clients (API v3 de VT, todas las APIs nuevas)
- Usa UnifiedThreatIntelClient para consultas multi-fuente
- Integración con mitre_service.py (PostgreSQL) en lugar del diccionario estático
- Score de confianza recalculado con todas las fuentes
"""
from typing import Any, Dict, List, Optional, Tuple
import logging
from app.services.new_api_clients import UnifiedThreatIntelClient
from app.services.llm_service import LLMService

# NUEVO: Importamos únicamente el servicio dinámico de la base de datos
from app.services.mitre_service import get_technique_info, get_techniques_by_malware

logger = logging.getLogger(__name__)


class ThreatIntelService:
    """Servicio principal de análisis de threat intelligence"""

    def __init__(self) -> None:
        self.unified_client = UnifiedThreatIntelClient()
        self.llm_service = LLMService()

    def analyze_ioc(self, ioc: str, ioc_type: str) -> Dict[str, Any]:
        """
        Análisis completo de un IOC con TODAS las fuentes disponibles

        Args:
            ioc: Valor del IOC
            ioc_type: Tipo (ip, hash, domain, url)

        Returns:
            Dict con resultados del análisis
        """
        results = {
            'ioc': ioc,
            'type': ioc_type,
            'api_results': {},
            'llm_analysis': None,
            'mitre_techniques': [],
            'confidence_score': 0,
            'risk_level': 'Unknown',
            'recommendation': '',
            'sources_used': [],
            'errors': [],
            # Campos legacy para compatibilidad con IOCAnalysis model
            'virustotal': None,
            'abuseipdb': None,
            'shodan': None,
            'otx': None,
        }

        # Ejecutar consultas según tipo de IOC
        try:
            if ioc_type == 'ip':
                logger.info(f"Analizando IP {ioc} en múltiples fuentes")
                api_results = self.unified_client.analyze_ip(ioc)

            elif ioc_type == 'domain':
                logger.info(f"Analizando dominio {ioc} en múltiples fuentes")
                api_results = self.unified_client.analyze_domain(ioc)

            elif ioc_type == 'hash':
                logger.info(f"Analizando hash {ioc} en múltiples fuentes")
                api_results = self.unified_client.analyze_hash(ioc)

            elif ioc_type == 'url':
                logger.info(f"Analizando URL {ioc} en múltiples fuentes")
                api_results = self.unified_client.analyze_url(ioc)

            else:
                results['errors'].append(f"Tipo de IOC no soportado: {ioc_type}")
                return results

            results['api_results'] = api_results

            # Registrar fuentes usadas y errores
            for source, data in api_results.items():
                if isinstance(data, dict):
                    if 'error' in data:
                        results['errors'].append(f"{source}: {data['error']}")
                    else:
                        results['sources_used'].append(source)

            # Mapear campos legacy para compatibilidad con BD
            results['virustotal'] = api_results.get('virustotal')
            results['abuseipdb'] = api_results.get('abuseipdb')
            results['shodan'] = api_results.get('shodan')
            results['otx'] = api_results.get('otx')

        except Exception as e:
            logger.error(f"Error en consultas API: {e}")
            results['errors'].append(f"Error general: {str(e)}")

        # Análisis MITRE ATT&CK
        malware_families = self._extract_malware_families(results)
        if malware_families:
            results['mitre_techniques'] = self._correlate_mitre_techniques(malware_families)

        # Calcular scores
        results['confidence_score'] = self._calculate_confidence_score(results)
        results['risk_level'] = self._determine_risk_level(results['confidence_score'])
        results['recommendation'] = self._generate_recommendation(results)

        # Análisis LLM (opcional)
        try:
            llm_result = self.llm_service.analyze_context(results)
            if llm_result and 'error' not in llm_result:
                results['llm_analysis'] = llm_result
            elif llm_result and 'error' in llm_result:
                results['errors'].append(f"LLM: {llm_result['error']}")
        except Exception as e:
            logger.error(f"LLM analysis error: {e}")
            results['errors'].append(f"LLM: {str(e)}")

        return results

    def _extract_malware_families(self, results: Dict[str, Any]) -> List[str]:
        """Extrae familias de malware de TODOS los resultados"""
        families = []
        api_results = results.get('api_results', {})

        # VirusTotal v3
        vt = api_results.get('virustotal', {})
        if vt and isinstance(vt, dict) and not vt.get('error'):
            ptc = vt.get('popular_threat_classification', {})
            if ptc:
                suggested = ptc.get('suggested_threat_label', '')
                if suggested:
                    families.append(suggested.split('/')[0])
                for item in ptc.get('popular_threat_name', []):
                    name = item.get('value', '')
                    if name:
                        families.append(name)

        # Hybrid Analysis
        ha = api_results.get('hybrid_analysis', {})
        if ha and isinstance(ha, dict) and not ha.get('error'):
            vx_family = ha.get('vx_family')
            if vx_family:
                families.append(vx_family)

        # MalwareBazaar
        mb = api_results.get('malwarebazaar', {})
        if mb and isinstance(mb, dict) and not mb.get('error'):
            signature = mb.get('signature')
            if signature:
                families.append(signature)

        # ThreatFox
        tf = api_results.get('threatfox', {})
        if tf and isinstance(tf, dict) and not tf.get('error'):
            malware = tf.get('malware')
            if malware:
                families.append(malware)

        # Pulsedive
        pd = api_results.get('pulsedive', {})
        if pd and isinstance(pd, dict) and not pd.get('error'):
            threats = pd.get('threats', [])
            for t in threats:
                if isinstance(t, dict):
                    families.append(t.get('name', ''))
                elif isinstance(t, str):
                    families.append(t)

        # OTX
        otx = api_results.get('otx', {})
        if otx and isinstance(otx, dict) and not otx.get('error'):
            for pulse in otx.get('pulses', []):
                if isinstance(pulse, dict):
                    for tag in pulse.get('tags', []):
                        if tag and len(tag) > 2:
                            families.append(tag)

        # Limpiar y deduplicar
        cleaned = list(set([f.strip().lower() for f in families if f and len(f.strip()) > 1]))
        return cleaned

    def _correlate_mitre_techniques(self, malware_families: List[str]) -> List[Dict[str, Any]]:
        """Correlaciona familias de malware con técnicas MITRE ATT&CK dinámicas desde la BD"""
        techniques = []
        seen_techniques = set()

        for family in malware_families:
            # 1. Disparamos la consulta a PostgreSQL usando el drop-in replacement
            techs_found = get_techniques_by_malware(family)

            for tech in techs_found:
                tech_id = tech.get('id')
                if tech_id not in seen_techniques:
                    # 2. Empaquetamos la información y agregamos el contexto de la familia
                    techniques.append({
                        'id': tech_id,
                        'name': tech.get('name', 'Unknown'),
                        'tactic': tech.get('tactic', 'Unknown'),
                        'malware_family': family
                    })
                    seen_techniques.add(tech_id)

        return techniques

    def _calculate_confidence_score(self, results: Dict[str, Any]) -> int:
        """
        Calcula score de confianza basado en TODAS las fuentes.
        Máximo 100 puntos distribuidos proporcionalmente.
        Las APIs principales (VT, AbuseIPDB, GreyNoise) son validadas con
        Pydantic para detectar discrepancias de schema silenciosas.
        """
        from app.schemas.api_responses import parse_virustotal, parse_abuseipdb, parse_greynoise

        score = 0
        api_results = results.get('api_results', {})

        # ── VirusTotal (hasta 25 puntos) ──
        vt_raw = api_results.get('virustotal', {})
        vt_parsed = parse_virustotal(vt_raw)
        if vt_parsed:
            if vt_parsed.malicious >= 10:
                score += 25
            elif vt_parsed.malicious >= 5:
                score += 18
            elif vt_parsed.malicious >= 1:
                score += 10
        elif vt_raw and isinstance(vt_raw, dict) and not vt_raw.get('error'):
            # Fallback sin validación (schema desconocido, usar raw)
            malicious = vt_raw.get('malicious', 0)
            if malicious:
                score += min(25, int(malicious * 2.5))

        # ── AbuseIPDB (hasta 15 puntos) ──
        abuse_raw = api_results.get('abuseipdb', {})
        abuse_parsed = parse_abuseipdb(abuse_raw)
        if abuse_parsed:
            score += min(15, int(abuse_parsed.abuse_confidence * 0.15))
        elif abuse_raw and isinstance(abuse_raw, dict) and not abuse_raw.get('error'):
            abuse_conf = abuse_raw.get('abuse_confidence_score', abuse_raw.get('abuse_confidence', 0))
            if abuse_conf:
                score += min(15, int(abuse_conf * 0.15))

        # ── Shodan (hasta 10 puntos) ──
        shodan = api_results.get('shodan', {})
        if shodan and isinstance(shodan, dict) and not shodan.get('error'):
            vulns = shodan.get('vulns', [])
            ports = shodan.get('ports', [])
            if vulns:
                score += min(7, len(vulns) * 2)
            dangerous_ports = [p for p in ports if p in [21, 22, 23, 3389, 445, 1433, 3306, 5432, 27017]]
            if dangerous_ports:
                score += min(3, len(dangerous_ports))

        # ── OTX (hasta 10 puntos) ──
        otx = api_results.get('otx', {})
        if otx and isinstance(otx, dict) and not otx.get('error'):
            pulse_count = otx.get('pulse_count', 0)
            if pulse_count:
                score += min(10, pulse_count * 2)

        # ── GreyNoise (hasta 8 puntos) ──
        gn_raw = api_results.get('greynoise', {})
        gn_parsed = parse_greynoise(gn_raw)
        if gn_parsed:
            if gn_parsed.classification == 'malicious':
                score += 8
            elif gn_parsed.classification == 'unknown' and gn_parsed.noise:
                score += 4
        elif gn_raw and isinstance(gn_raw, dict) and not gn_raw.get('error'):
            classification = gn_raw.get('classification', '')
            if classification == 'malicious':
                score += 8
            elif classification == 'unknown' and gn_raw.get('noise'):
                score += 4

        # ── Criminal IP (hasta 8 puntos) ──
        cip = api_results.get('criminal_ip', {})
        if cip and isinstance(cip, dict) and not cip.get('error'):
            if cip.get('is_malicious'):
                score += 8
            elif cip.get('is_scanner') or cip.get('is_tor') or cip.get('is_proxy'):
                score += 4
            cip_score = cip.get('score')
            if cip_score and isinstance(cip_score, (int, float)):
                if cip_score >= 80:
                    score += 4

        # ── Pulsedive (hasta 6 puntos) ──
        pd = api_results.get('pulsedive', {})
        if pd and isinstance(pd, dict) and not pd.get('error') and pd.get('found'):
            risk = pd.get('risk', '')
            if risk == 'critical':
                score += 6
            elif risk == 'high':
                score += 4
            elif risk == 'medium':
                score += 2

        # ── Google Safe Browsing (hasta 6 puntos) ──
        gsb = api_results.get('safebrowsing', {}) or api_results.get('google_safebrowsing', {})
        if gsb and isinstance(gsb, dict) and not gsb.get('error'):
            if gsb.get('is_malicious'):
                score += 6

        # ── ThreatFox (hasta 5 puntos) ──
        tf = api_results.get('threatfox', {})
        if tf and isinstance(tf, dict) and not tf.get('error'):
            if tf.get('found'):
                confidence = tf.get('confidence_level', 0)
                if confidence and confidence >= 75:
                    score += 5
                elif confidence and confidence >= 50:
                    score += 3
                else:
                    score += 2

        # ── URLhaus (hasta 4 puntos) ──
        uh = api_results.get('urlhaus', {})
        if uh and isinstance(uh, dict) and not uh.get('error'):
            if uh.get('found'):
                url_status = uh.get('url_status', '')
                if url_status == 'online':
                    score += 4
                else:
                    score += 2

        # ── MalwareBazaar + Hybrid Analysis (hasta 3 puntos) ──
        mb = api_results.get('malwarebazaar', {})
        if mb and isinstance(mb, dict) and not mb.get('error') and mb.get('found'):
            score += 2

        ha = api_results.get('hybrid_analysis', {})
        if ha and isinstance(ha, dict) and not ha.get('error') and ha.get('found'):
            verdict = ha.get('verdict', '')
            if verdict == 'malicious':
                score += 3
            elif verdict == 'suspicious':
                score += 1

        # ── MITRE ATT&CK bonus (hasta 5 puntos) ──
        techniques = results.get('mitre_techniques', [])
        if techniques and isinstance(techniques, list):
            score += min(5, len(techniques) * 2)

        return min(100, max(0, score))

    def _determine_risk_level(self, confidence: int) -> str:
        """Determina nivel de riesgo basado en confidence score"""
        if confidence >= 70:
            return "CRÍTICO"
        elif confidence >= 50:
            return "ALTO"
        elif confidence >= 30:
            return "MEDIO"
        elif confidence >= 15:
            return "BAJO"
        else:
            return "LIMPIO"

    def _generate_recommendation(self, results: Dict[str, Any]) -> str:
        """Genera recomendaciones basadas en los resultados"""
        confidence = results['confidence_score']
        recommendations = []

        if confidence >= 70:
            recommendations.append("⚠️ ACCIÓN INMEDIATA REQUERIDA")
            recommendations.append("1. BLOQUEAR INMEDIATAMENTE en firewall/IDS/IPS")
            recommendations.append("2. Crear ticket de incidente P1")
            recommendations.append("3. Investigar logs relacionados en SIEM")
            recommendations.append("4. Buscar indicadores de compromiso relacionados")
            recommendations.append("5. Notificar al equipo de respuesta a incidentes")
        elif confidence >= 50:
            recommendations.append("⚠️ AMENAZA ALTA DETECTADA")
            recommendations.append("1. Implementar bloqueo preventivo")
            recommendations.append("2. Crear ticket P2")
            recommendations.append("3. Monitoreo intensivo durante 24-48h")
            recommendations.append("4. Revisar contexto de detección")
        elif confidence >= 30:
            recommendations.append("⚡ MONITOREO ACTIVO")
            recommendations.append("1. Incrementar nivel de logging")
            recommendations.append("2. Observar comportamiento")
            recommendations.append("3. Revisar en 24 horas")
            recommendations.append("4. Documentar hallazgos")
        elif confidence >= 15:
            recommendations.append("📋 DOCUMENTAR")
            recommendations.append("1. Registrar en base de conocimiento")
            recommendations.append("2. Monitoreo pasivo")
            recommendations.append("3. Revisar si aparece nuevamente")
        else:
            recommendations.append("✅ NO SE DETECTARON AMENAZAS")
            recommendations.append("IOC limpio según las fuentes consultadas")

        api_results = results.get('api_results', {})

        # Recomendaciones específicas por fuente
        shodan = api_results.get('shodan', {})
        if shodan and isinstance(shodan, dict) and not shodan.get('error'):
            vulns = shodan.get('vulns', [])
            if vulns:
                recommendations.append(
                    f"🔓 Vulnerabilidades detectadas (Shodan): {', '.join(str(v) for v in vulns[:5])}"
                )

        gn = api_results.get('greynoise', {})
        if gn and isinstance(gn, dict) and not gn.get('error'):
            if gn.get('noise') and gn.get('classification') == 'malicious':
                recommendations.append("🌐 GreyNoise: IP detectada como escáner malicioso activo")
            elif gn.get('riot'):
                recommendations.append("✅ GreyNoise RIOT: IP pertenece a servicio legítimo conocido")

        cip = api_results.get('criminal_ip', {})
        if cip and isinstance(cip, dict) and not cip.get('error'):
            flags = []
            if cip.get('is_vpn'): flags.append('VPN')
            if cip.get('is_tor'): flags.append('Tor')
            if cip.get('is_proxy'): flags.append('Proxy')
            if cip.get('is_scanner'): flags.append('Scanner')
            if flags:
                recommendations.append(f"🔍 Criminal IP flags: {', '.join(flags)}")

        otx = api_results.get('otx', {})
        if otx and isinstance(otx, dict) and not otx.get('error'):
            pulse_count = otx.get('pulse_count', 0)
            if pulse_count and pulse_count > 5:
                recommendations.append(
                    f"📊 Alta actividad en threat intelligence: {pulse_count} pulsos OTX"
                )

        if results.get('mitre_techniques'):
            tactics = list(set([t['tactic'] for t in results['mitre_techniques']]))
            recommendations.append(
                f"🎯 Tácticas MITRE identificadas: {', '.join(tactics[:5])}"
            )

        # Resumen de fuentes
        sources = results.get('sources_used', [])
        if sources:
            recommendations.append(
                f"\n📡 Fuentes consultadas ({len(sources)}): {', '.join(sources)}"
            )

        return "\n".join(recommendations)

    def batch_analyze(self, iocs: List[Tuple[str, str]]) -> List[Dict[str, Any]]:
        """
        Analiza múltiples IOCs

        Args:
            iocs: Lista de tuplas (ioc_value, ioc_type)

        Returns:
            Lista de resultados
        """
        results = []

        for ioc_value, ioc_type in iocs:
            try:
                result = self.analyze_ioc(ioc_value, ioc_type)
                results.append(result)
            except Exception as e:
                logger.error(f"Error analyzing {ioc_value}: {e}")
                results.append({
                    'ioc': ioc_value,
                    'type': ioc_type,
                    'error': str(e)
                })

        return results