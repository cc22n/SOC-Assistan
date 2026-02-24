"""
Deep Analysis Service - SOC Agent
Sistema de análisis profundo con múltiples capas de investigación

Capacidades:
1. Búsqueda web en tiempo real (OSINT)
2. Correlación automática entre IOCs
3. Identificación de campañas/APTs
4. Generación de hipótesis de ataque

Nivel: Balanceado (3-5 consultas LLM)
"""
import logging
import re
import json
import requests
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from flask import current_app

logger = logging.getLogger(__name__)


class DeepAnalysisService:
    """
    Servicio de análisis profundo para IOCs.
    Combina APIs de threat intel + búsqueda web + análisis LLM avanzado.
    """
    
    def __init__(self):
        self._llm_service = None
        self._orchestrator = None
        
        # Base de conocimiento de APTs (simplificada)
        self.apt_indicators = {
            # APT29 (Cozy Bear) - Russia
            'APT29': {
                'aliases': ['Cozy Bear', 'The Dukes', 'YTTRIUM'],
                'country': 'Russia',
                'targets': ['government', 'diplomatic', 'think tanks'],
                'tools': ['Cobalt Strike', 'WellMess', 'WellMail', 'SUNBURST'],
                'ttps': ['T1566', 'T1059', 'T1071', 'T1027', 'T1083'],
                'indicators': ['cozy', 'duke', 'wellmess', 'solarwinds']
            },
            # APT28 (Fancy Bear) - Russia
            'APT28': {
                'aliases': ['Fancy Bear', 'Sofacy', 'STRONTIUM', 'Sednit'],
                'country': 'Russia',
                'targets': ['military', 'government', 'media', 'elections'],
                'tools': ['X-Agent', 'Zebrocy', 'Komplex'],
                'ttps': ['T1566.001', 'T1059.001', 'T1071.001', 'T1078'],
                'indicators': ['sofacy', 'xagent', 'zebrocy', 'sednit']
            },
            # Lazarus Group - North Korea
            'Lazarus': {
                'aliases': ['Hidden Cobra', 'Zinc', 'Guardians of Peace'],
                'country': 'North Korea',
                'targets': ['financial', 'cryptocurrency', 'defense'],
                'tools': ['FALLCHILL', 'Manuscrypt', 'AppleJeus'],
                'ttps': ['T1566', 'T1059', 'T1486', 'T1565'],
                'indicators': ['lazarus', 'hidden cobra', 'applejeus', 'manuscrypt']
            },
            # Emotet
            'Emotet': {
                'aliases': ['Heodo', 'Geodo'],
                'country': 'Unknown (Cybercrime)',
                'targets': ['all sectors', 'banking', 'corporate'],
                'tools': ['Emotet', 'TrickBot', 'Ryuk'],
                'ttps': ['T1566.001', 'T1059.005', 'T1055', 'T1486'],
                'indicators': ['emotet', 'heodo', 'epoch', 'trickbot']
            },
            # Cobalt Strike (Tool, not APT)
            'Cobalt Strike': {
                'aliases': ['Beacon', 'CS'],
                'country': 'Multiple (Commercial Tool)',
                'targets': ['all sectors'],
                'tools': ['Beacon', 'Cobalt Strike'],
                'ttps': ['T1059', 'T1071', 'T1055', 'T1105'],
                'indicators': ['cobalt', 'beacon', 'cobaltstrike', 'cs_']
            },
            # QakBot
            'QakBot': {
                'aliases': ['Qbot', 'QuakBot', 'Pinkslipbot'],
                'country': 'Unknown (Cybercrime)',
                'targets': ['banking', 'corporate'],
                'tools': ['QakBot', 'Cobalt Strike'],
                'ttps': ['T1566.001', 'T1059.001', 'T1055', 'T1071'],
                'indicators': ['qakbot', 'qbot', 'quakbot', 'pinkslip']
            },
            # LockBit (Ransomware)
            'LockBit': {
                'aliases': ['LockBit 2.0', 'LockBit 3.0', 'LockBit Black'],
                'country': 'Unknown (Ransomware-as-a-Service)',
                'targets': ['all sectors', 'critical infrastructure'],
                'tools': ['LockBit', 'StealBit'],
                'ttps': ['T1486', 'T1490', 'T1027', 'T1070'],
                'indicators': ['lockbit', 'stealbit', '.lockbit']
            },
        }
        
        # MITRE ATT&CK técnicas comunes
        self.mitre_techniques = {
            'T1566': 'Phishing',
            'T1566.001': 'Spearphishing Attachment',
            'T1566.002': 'Spearphishing Link',
            'T1059': 'Command and Scripting Interpreter',
            'T1059.001': 'PowerShell',
            'T1059.005': 'Visual Basic',
            'T1071': 'Application Layer Protocol',
            'T1071.001': 'Web Protocols',
            'T1055': 'Process Injection',
            'T1027': 'Obfuscated Files or Information',
            'T1083': 'File and Directory Discovery',
            'T1078': 'Valid Accounts',
            'T1486': 'Data Encrypted for Impact',
            'T1490': 'Inhibit System Recovery',
            'T1105': 'Ingress Tool Transfer',
            'T1565': 'Data Manipulation',
            'T1070': 'Indicator Removal',
            'T1046': 'Network Service Discovery',
            'T1595': 'Active Scanning',
            'T1595.001': 'Scanning IP Blocks',
            'T1583': 'Acquire Infrastructure',
            'T1204': 'User Execution',
        }
    
    @property
    def llm_service(self):
        if self._llm_service is None:
            from app.services.llm_service import LLMService
            self._llm_service = LLMService()
        return self._llm_service
    
    @property
    def orchestrator(self):
        if self._orchestrator is None:
            from app.services.llm_orchestrator import LLMOrchestrator
            self._orchestrator = LLMOrchestrator()
        return self._orchestrator
    
    # =========================================================================
    # MÉTODO PRINCIPAL: DEEP ANALYSIS
    # =========================================================================
    
    def deep_analyze(
        self,
        ioc: str,
        ioc_type: str,
        user_id: int = None,
        session_id: int = None,
        include_web_search: bool = True,
        include_correlation: bool = True,
        include_apt_analysis: bool = True,
        include_hypothesis: bool = True
    ) -> Dict:
        """
        Ejecuta análisis profundo de un IOC.
        
        Args:
            ioc: Valor del IOC
            ioc_type: Tipo (ip/domain/url/hash)
            user_id: ID del usuario
            session_id: ID de sesión para correlación
            include_*: Flags para habilitar/deshabilitar módulos
        
        Returns:
            Dict con análisis completo
        """
        start_time = datetime.utcnow()
        logger.info(f"🔍 Starting deep analysis for {ioc_type}: {ioc}")
        
        results = {
            'ioc': ioc,
            'ioc_type': ioc_type,
            'timestamp': start_time.isoformat(),
            'modules_executed': [],
            'errors': []
        }
        
        try:
            # ─────────────────────────────────────────────────────────────────
            # PASO 1: Análisis base con APIs existentes
            # ─────────────────────────────────────────────────────────────────
            logger.info("📡 Step 1: Base API analysis...")
            base_analysis = self.orchestrator.analyze_with_intelligence(
                ioc=ioc,
                ioc_type=ioc_type,
                user_context="Análisis profundo solicitado",
                use_llm_planning=True
            )
            results['base_analysis'] = base_analysis
            results['modules_executed'].append('base_apis')
            
            # ─────────────────────────────────────────────────────────────────
            # PASO 2: Búsqueda web OSINT
            # ─────────────────────────────────────────────────────────────────
            if include_web_search:
                logger.info("🌐 Step 2: Web search (OSINT)...")
                try:
                    web_results = self._web_search_osint(ioc, ioc_type)
                    results['web_search'] = web_results
                    results['modules_executed'].append('web_search')
                except Exception as e:
                    logger.error(f"Web search error: {e}")
                    results['errors'].append(f"web_search: {str(e)}")
            
            # ─────────────────────────────────────────────────────────────────
            # PASO 3: Correlación con otros IOCs
            # ─────────────────────────────────────────────────────────────────
            if include_correlation and session_id:
                logger.info("🔗 Step 3: IOC correlation...")
                try:
                    correlations = self._correlate_iocs(ioc, ioc_type, session_id)
                    results['correlations'] = correlations
                    results['modules_executed'].append('correlation')
                except Exception as e:
                    logger.error(f"Correlation error: {e}")
                    results['errors'].append(f"correlation: {str(e)}")
            
            # ─────────────────────────────────────────────────────────────────
            # PASO 4: Identificación de APT/Campaña
            # ─────────────────────────────────────────────────────────────────
            if include_apt_analysis:
                logger.info("🎯 Step 4: APT/Campaign identification...")
                try:
                    apt_analysis = self._identify_apt_campaign(
                        ioc, ioc_type, base_analysis, 
                        results.get('web_search', {})
                    )
                    results['apt_analysis'] = apt_analysis
                    results['modules_executed'].append('apt_identification')
                except Exception as e:
                    logger.error(f"APT analysis error: {e}")
                    results['errors'].append(f"apt_analysis: {str(e)}")
            
            # ─────────────────────────────────────────────────────────────────
            # PASO 5: Generación de hipótesis
            # ─────────────────────────────────────────────────────────────────
            if include_hypothesis:
                logger.info("🧩 Step 5: Attack hypothesis generation...")
                try:
                    hypothesis = self._generate_attack_hypothesis(
                        ioc, ioc_type, results
                    )
                    results['hypothesis'] = hypothesis
                    results['modules_executed'].append('hypothesis')
                except Exception as e:
                    logger.error(f"Hypothesis error: {e}")
                    results['errors'].append(f"hypothesis: {str(e)}")
            
            # ─────────────────────────────────────────────────────────────────
            # PASO 6: Generar reporte final con LLM
            # ─────────────────────────────────────────────────────────────────
            logger.info("📋 Step 6: Generating final report...")
            final_report = self._generate_deep_report(results)
            results['final_report'] = final_report
            
            # Calcular tiempo total
            results['processing_time'] = (datetime.utcnow() - start_time).total_seconds()
            logger.info(f"✅ Deep analysis completed in {results['processing_time']:.2f}s")
            
            return results
            
        except Exception as e:
            logger.error(f"Deep analysis failed: {e}")
            results['errors'].append(f"critical: {str(e)}")
            results['processing_time'] = (datetime.utcnow() - start_time).total_seconds()
            return results
    
    # =========================================================================
    # MÓDULO 2: BÚSQUEDA WEB OSINT
    # =========================================================================
    
    def _web_search_osint(self, ioc: str, ioc_type: str) -> Dict:
        """
        Realiza búsqueda web para encontrar información OSINT sobre el IOC.
        Usa DuckDuckGo (no requiere API key) o Google Custom Search.
        """
        results = {
            'sources_found': [],
            'mentions': [],
            'threat_reports': [],
            'news': [],
            'raw_results': []
        }
        
        # Construir queries de búsqueda
        search_queries = [
            f'"{ioc}" malware threat',
            f'"{ioc}" cyber attack report',
            f'"{ioc}" IOC indicator compromise',
        ]
        
        if ioc_type == 'ip':
            search_queries.append(f'"{ioc}" botnet C2')
        elif ioc_type == 'hash':
            search_queries.append(f'"{ioc}" virus sample analysis')
        elif ioc_type == 'domain':
            search_queries.append(f'"{ioc}" phishing malicious')
        
        # Intentar DuckDuckGo Instant Answer API (gratuito, limitado)
        for query in search_queries[:2]:  # Limitar a 2 queries
            try:
                ddg_results = self._search_duckduckgo(query)
                if ddg_results:
                    results['raw_results'].extend(ddg_results)
            except Exception as e:
                logger.warning(f"DuckDuckGo search failed: {e}")
        
        # Buscar en fuentes de threat intel conocidas
        threat_intel_sources = self._search_threat_intel_sources(ioc, ioc_type)
        results['threat_reports'] = threat_intel_sources
        
        # Usar LLM para analizar y resumir los resultados
        if results['raw_results'] or results['threat_reports']:
            summary = self._summarize_web_results(ioc, results)
            results['summary'] = summary
        
        return results
    
    def _search_duckduckgo(self, query: str) -> List[Dict]:
        """Búsqueda usando DuckDuckGo Instant Answer API"""
        try:
            url = "https://api.duckduckgo.com/"
            params = {
                'q': query,
                'format': 'json',
                'no_html': 1,
                'skip_disambig': 1
            }
            
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                results = []
                
                # Abstract (resumen principal)
                if data.get('Abstract'):
                    results.append({
                        'title': data.get('Heading', 'Result'),
                        'snippet': data.get('Abstract'),
                        'source': data.get('AbstractSource', 'DuckDuckGo'),
                        'url': data.get('AbstractURL', '')
                    })
                
                # Related topics
                for topic in data.get('RelatedTopics', [])[:3]:
                    if isinstance(topic, dict) and topic.get('Text'):
                        results.append({
                            'title': topic.get('Text', '')[:50],
                            'snippet': topic.get('Text', ''),
                            'url': topic.get('FirstURL', '')
                        })
                
                return results
            return []
            
        except Exception as e:
            logger.warning(f"DuckDuckGo API error: {e}")
            return []
    
    def _search_threat_intel_sources(self, ioc: str, ioc_type: str) -> List[Dict]:
        """
        Genera URLs de búsqueda en fuentes conocidas de threat intel.
        No hace scraping, solo proporciona enlaces útiles.
        """
        sources = []
        
        # URLs de búsqueda en fuentes públicas
        if ioc_type == 'ip':
            sources = [
                {
                    'name': 'AbuseIPDB',
                    'url': f'https://www.abuseipdb.com/check/{ioc}',
                    'type': 'reputation'
                },
                {
                    'name': 'Shodan',
                    'url': f'https://www.shodan.io/host/{ioc}',
                    'type': 'infrastructure'
                },
                {
                    'name': 'GreyNoise',
                    'url': f'https://viz.greynoise.io/ip/{ioc}',
                    'type': 'noise_classification'
                },
                {
                    'name': 'Censys',
                    'url': f'https://search.censys.io/hosts/{ioc}',
                    'type': 'infrastructure'
                },
                {
                    'name': 'IPVoid',
                    'url': f'https://www.ipvoid.com/ip-blacklist-check/?ip={ioc}',
                    'type': 'blacklist'
                },
            ]
        elif ioc_type == 'domain':
            sources = [
                {
                    'name': 'VirusTotal',
                    'url': f'https://www.virustotal.com/gui/domain/{ioc}',
                    'type': 'reputation'
                },
                {
                    'name': 'URLhaus',
                    'url': f'https://urlhaus.abuse.ch/browse.php?search={ioc}',
                    'type': 'malware_urls'
                },
                {
                    'name': 'URLScan',
                    'url': f'https://urlscan.io/search/#{ioc}',
                    'type': 'visual_scan'
                },
                {
                    'name': 'SecurityTrails',
                    'url': f'https://securitytrails.com/domain/{ioc}',
                    'type': 'dns_history'
                },
            ]
        elif ioc_type == 'hash':
            sources = [
                {
                    'name': 'VirusTotal',
                    'url': f'https://www.virustotal.com/gui/file/{ioc}',
                    'type': 'malware_analysis'
                },
                {
                    'name': 'MalwareBazaar',
                    'url': f'https://bazaar.abuse.ch/browse.php?search=sha256:{ioc}',
                    'type': 'malware_samples'
                },
                {
                    'name': 'Hybrid Analysis',
                    'url': f'https://www.hybrid-analysis.com/search?query={ioc}',
                    'type': 'sandbox'
                },
                {
                    'name': 'Any.Run',
                    'url': f'https://any.run/report/{ioc}',
                    'type': 'sandbox'
                },
            ]
        elif ioc_type == 'url':
            sources = [
                {
                    'name': 'URLhaus',
                    'url': f'https://urlhaus.abuse.ch/browse.php?search={ioc}',
                    'type': 'malware_urls'
                },
                {
                    'name': 'Google Safe Browsing',
                    'url': f'https://transparencyreport.google.com/safe-browsing/search?url={ioc}',
                    'type': 'safe_browsing'
                },
            ]
        
        return sources
    
    def _summarize_web_results(self, ioc: str, web_results: Dict) -> str:
        """Usa LLM para resumir los resultados de búsqueda web"""
        prompt = f"""Analiza estos resultados de búsqueda web sobre el IOC: {ioc}

Resultados encontrados:
{json.dumps(web_results.get('raw_results', []), indent=2)}

Fuentes de threat intel disponibles:
{json.dumps(web_results.get('threat_reports', []), indent=2)}

Resume en 2-3 oraciones:
1. ¿Se encontró información relevante sobre este IOC?
2. ¿Qué fuentes mencionan actividad maliciosa?
3. ¿Hay reportes de seguridad que lo mencionen?

Responde de forma concisa y profesional."""

        try:
            response = self.llm_service._call_generic_openai_style(prompt)
            if isinstance(response, dict):
                return response.get('analysis') or response.get('content') or str(response)
            return str(response)
        except Exception as e:
            logger.error(f"LLM summarization error: {e}")
            return "No se pudo generar resumen de búsqueda web."
    
    # =========================================================================
    # MÓDULO 3: CORRELACIÓN DE IOCs
    # =========================================================================
    
    def _correlate_iocs(self, ioc: str, ioc_type: str, session_id: int) -> Dict:
        """
        Busca correlaciones entre el IOC actual y otros de la sesión/BD.
        """
        correlations = {
            'related_iocs': [],
            'shared_infrastructure': [],
            'common_campaigns': [],
            'correlation_score': 0,
            'analysis': ''
        }
        
        try:
            from app.models.ioc import IOCAnalysis, IOC
            from app.models.session import SessionIOC
            from app import db
            
            # Obtener IOCs de la sesión actual
            session_iocs = db.session.query(SessionIOC).filter(
                SessionIOC.session_id == session_id
            ).all()
            
            other_iocs = []
            for sioc in session_iocs:
                if sioc.ioc and sioc.ioc.value != ioc:
                    other_iocs.append({
                        'value': sioc.ioc.value,
                        'type': sioc.ioc.ioc_type,
                        'analysis': sioc.analysis.to_dict() if sioc.analysis else None
                    })
            
            if not other_iocs:
                correlations['analysis'] = "No hay otros IOCs en la sesión para correlacionar."
                return correlations
            
            # Buscar correlaciones con LLM
            prompt = f"""Eres un analista de threat intelligence. Analiza las posibles correlaciones entre estos IOCs:

IOC Principal: {ioc} ({ioc_type})

Otros IOCs en la investigación:
{json.dumps(other_iocs, indent=2, default=str)}

Busca:
1. ¿Comparten infraestructura (mismo ASN, hosting, país)?
2. ¿Podrían pertenecer a la misma campaña?
3. ¿Hay patrones que los conecten?
4. ¿Alguno podría ser C2 del otro?

Responde en JSON:
{{
    "related_pairs": [
        {{"ioc1": "...", "ioc2": "...", "relationship": "...", "confidence": "alta/media/baja"}}
    ],
    "shared_indicators": ["indicador1", "indicador2"],
    "possible_campaign": "nombre o descripción",
    "correlation_summary": "Resumen de 2-3 oraciones"
}}"""

            response = self.llm_service._call_generic_openai_style(prompt)
            
            if isinstance(response, dict):
                text = response.get('analysis') or response.get('content') or ''
            else:
                text = str(response)
            
            # Parsear JSON de la respuesta
            json_match = re.search(r'\{.*\}', text, re.DOTALL)
            if json_match:
                try:
                    correlation_data = json.loads(json_match.group(0))
                    correlations['related_iocs'] = correlation_data.get('related_pairs', [])
                    correlations['shared_infrastructure'] = correlation_data.get('shared_indicators', [])
                    correlations['common_campaigns'] = [correlation_data.get('possible_campaign')] if correlation_data.get('possible_campaign') else []
                    correlations['analysis'] = correlation_data.get('correlation_summary', '')
                except json.JSONDecodeError:
                    correlations['analysis'] = text
            else:
                correlations['analysis'] = text
            
            # Calcular score de correlación
            correlations['correlation_score'] = len(correlations['related_iocs']) * 20 + \
                                                len(correlations['shared_infrastructure']) * 10
            
        except Exception as e:
            logger.error(f"Correlation error: {e}")
            correlations['analysis'] = f"Error en correlación: {str(e)}"
        
        return correlations
    
    # =========================================================================
    # MÓDULO 4: IDENTIFICACIÓN DE APT/CAMPAÑA
    # =========================================================================
    
    def _identify_apt_campaign(
        self, 
        ioc: str, 
        ioc_type: str, 
        base_analysis: Dict,
        web_results: Dict
    ) -> Dict:
        """
        Intenta identificar si el IOC está asociado a un APT o campaña conocida.
        """
        apt_result = {
            'identified_apt': None,
            'confidence': 'low',
            'evidence': [],
            'mitre_techniques': [],
            'recommendations': [],
            'analysis': ''
        }
        
        # Recopilar toda la información disponible
        all_data = {
            'ioc': ioc,
            'type': ioc_type,
            'api_results': base_analysis.get('api_results', {}),
            'risk_level': base_analysis.get('risk_level'),
            'web_findings': web_results.get('summary', ''),
        }
        
        # Primero, búsqueda rápida en nuestra base de conocimiento
        local_matches = self._search_local_apt_db(ioc, str(all_data))
        
        # Luego, análisis con LLM
        prompt = f"""Eres un experto en threat intelligence y APTs. Analiza este IOC y determina si está asociado a algún grupo de amenazas conocido.

IOC: {ioc} ({ioc_type})
Nivel de riesgo: {base_analysis.get('risk_level', 'DESCONOCIDO')}

Datos de APIs:
{json.dumps(base_analysis.get('api_results', {}), indent=2, default=str)[:3000]}

Información web encontrada:
{web_results.get('summary', 'No disponible')}

Coincidencias locales con APTs conocidos:
{json.dumps(local_matches, indent=2)}

GRUPOS APT CONOCIDOS (referencia):
- APT29 (Cozy Bear): Rusia, gobierno/diplomático, Cobalt Strike, WellMess
- APT28 (Fancy Bear): Rusia, militar/gobierno, X-Agent, Zebrocy
- Lazarus: Corea del Norte, financiero/cripto, FALLCHILL
- Emotet: Cibercrimen, banking, TrickBot, Ryuk
- QakBot: Cibercrimen, banking trojans
- LockBit: Ransomware-as-a-Service

Responde en JSON:
{{
    "identified_apt": "nombre del APT o null",
    "confidence": "high/medium/low",
    "evidence": ["evidencia 1", "evidencia 2"],
    "mitre_techniques": ["T1566", "T1059"],
    "related_malware": ["malware1", "malware2"],
    "attribution_reasoning": "Explicación de por qué crees que es este APT",
    "recommendations": ["recomendación 1", "recomendación 2"]
}}

Si no hay suficiente evidencia para atribuir a un APT específico, indica "identified_apt": null y explica qué tipo de amenaza parece ser."""

        try:
            response = self.llm_service._call_generic_openai_style(prompt)
            
            if isinstance(response, dict):
                text = response.get('analysis') or response.get('content') or ''
            else:
                text = str(response)
            
            # Parsear JSON
            json_match = re.search(r'\{.*\}', text, re.DOTALL)
            if json_match:
                try:
                    apt_data = json.loads(json_match.group(0))
                    apt_result['identified_apt'] = apt_data.get('identified_apt')
                    apt_result['confidence'] = apt_data.get('confidence', 'low')
                    apt_result['evidence'] = apt_data.get('evidence', [])
                    apt_result['mitre_techniques'] = apt_data.get('mitre_techniques', [])
                    apt_result['related_malware'] = apt_data.get('related_malware', [])
                    apt_result['recommendations'] = apt_data.get('recommendations', [])
                    apt_result['analysis'] = apt_data.get('attribution_reasoning', '')
                except json.JSONDecodeError:
                    apt_result['analysis'] = text
            else:
                apt_result['analysis'] = text
            
            # Enriquecer con descripciones de MITRE
            apt_result['mitre_details'] = [
                {'id': t, 'name': self.mitre_techniques.get(t, 'Unknown')}
                for t in apt_result['mitre_techniques']
            ]
            
        except Exception as e:
            logger.error(f"APT identification error: {e}")
            apt_result['analysis'] = f"Error en identificación: {str(e)}"
        
        return apt_result
    
    def _search_local_apt_db(self, ioc: str, data_str: str) -> List[Dict]:
        """Busca coincidencias en la base de conocimiento local de APTs"""
        matches = []
        data_lower = data_str.lower()
        
        for apt_name, apt_info in self.apt_indicators.items():
            score = 0
            evidence = []
            
            # Buscar indicadores
            for indicator in apt_info.get('indicators', []):
                if indicator.lower() in data_lower:
                    score += 30
                    evidence.append(f"Indicador encontrado: {indicator}")
            
            # Buscar tools
            for tool in apt_info.get('tools', []):
                if tool.lower() in data_lower:
                    score += 25
                    evidence.append(f"Herramienta detectada: {tool}")
            
            if score > 0:
                matches.append({
                    'apt': apt_name,
                    'aliases': apt_info.get('aliases', []),
                    'country': apt_info.get('country'),
                    'score': score,
                    'evidence': evidence
                })
        
        # Ordenar por score
        matches.sort(key=lambda x: x['score'], reverse=True)
        return matches[:3]  # Top 3
    
    # =========================================================================
    # MÓDULO 5: GENERACIÓN DE HIPÓTESIS
    # =========================================================================
    
    def _generate_attack_hypothesis(self, ioc: str, ioc_type: str, all_results: Dict) -> Dict:
        """
        Genera hipótesis sobre el ataque basándose en toda la información recopilada.
        """
        hypothesis = {
            'attack_scenario': '',
            'kill_chain_phase': '',
            'probable_vector': '',
            'attacker_objective': '',
            'next_steps_prediction': [],
            'defensive_recommendations': [],
            'confidence': 'medium'
        }
        
        prompt = f"""Eres un analista senior de threat intelligence. Basándote en toda la información recopilada, genera una hipótesis sobre este posible ataque.

IOC Analizado: {ioc} ({ioc_type})

=== ANÁLISIS BASE ===
Riesgo: {all_results.get('base_analysis', {}).get('risk_level', 'N/A')}
Score: {all_results.get('base_analysis', {}).get('confidence_score', 'N/A')}
APIs consultadas: {all_results.get('base_analysis', {}).get('sources_used', [])}

=== BÚSQUEDA WEB ===
{all_results.get('web_search', {}).get('summary', 'No disponible')}

=== CORRELACIONES ===
{all_results.get('correlations', {}).get('analysis', 'No disponible')}

=== ATRIBUCIÓN APT ===
APT identificado: {all_results.get('apt_analysis', {}).get('identified_apt', 'No identificado')}
Confianza: {all_results.get('apt_analysis', {}).get('confidence', 'N/A')}
Análisis: {all_results.get('apt_analysis', {}).get('analysis', 'N/A')}

Genera una hipótesis completa en JSON:
{{
    "attack_scenario": "Descripción del escenario de ataque más probable (2-3 oraciones)",
    "kill_chain_phase": "Fase del Cyber Kill Chain (Reconnaissance/Weaponization/Delivery/Exploitation/Installation/C2/Actions)",
    "probable_vector": "Vector de ataque más probable (phishing/exploit/supply-chain/etc)",
    "attacker_objective": "Objetivo probable del atacante (espionage/financial/ransomware/etc)",
    "next_steps_prediction": [
        "Predicción 1 de lo que hará el atacante",
        "Predicción 2",
        "Predicción 3"
    ],
    "defensive_recommendations": [
        "Acción defensiva inmediata 1",
        "Acción defensiva 2",
        "Acción defensiva 3",
        "Acción defensiva 4"
    ],
    "confidence": "high/medium/low",
    "reasoning": "Explicación de por qué esta hipótesis es la más probable"
}}"""

        try:
            response = self.llm_service._call_generic_openai_style(prompt)
            
            if isinstance(response, dict):
                text = response.get('analysis') or response.get('content') or ''
            else:
                text = str(response)
            
            # Parsear JSON
            json_match = re.search(r'\{.*\}', text, re.DOTALL)
            if json_match:
                try:
                    hyp_data = json.loads(json_match.group(0))
                    hypothesis.update(hyp_data)
                except json.JSONDecodeError:
                    hypothesis['attack_scenario'] = text
            else:
                hypothesis['attack_scenario'] = text
                
        except Exception as e:
            logger.error(f"Hypothesis generation error: {e}")
            hypothesis['attack_scenario'] = f"Error generando hipótesis: {str(e)}"
        
        return hypothesis
    
    # =========================================================================
    # GENERACIÓN DE REPORTE FINAL
    # =========================================================================
    
    def _generate_deep_report(self, all_results: Dict) -> Dict:
        """
        Genera un reporte final consolidado con todos los hallazgos.
        """
        ioc = all_results.get('ioc', 'N/A')
        ioc_type = all_results.get('ioc_type', 'N/A')
        
        prompt = f"""Genera un reporte ejecutivo de threat intelligence basado en este análisis profundo.

IOC: {ioc} ({ioc_type})

Módulos ejecutados: {all_results.get('modules_executed', [])}

=== RESUMEN DE HALLAZGOS ===

1. ANÁLISIS BASE:
   - Riesgo: {all_results.get('base_analysis', {}).get('risk_level', 'N/A')}
   - Score: {all_results.get('base_analysis', {}).get('confidence_score', 'N/A')}

2. OSINT WEB:
   {all_results.get('web_search', {}).get('summary', 'No ejecutado')}

3. CORRELACIONES:
   {all_results.get('correlations', {}).get('analysis', 'No ejecutado')}

4. ATRIBUCIÓN:
   - APT: {all_results.get('apt_analysis', {}).get('identified_apt', 'No identificado')}
   - MITRE: {all_results.get('apt_analysis', {}).get('mitre_techniques', [])}

5. HIPÓTESIS:
   {all_results.get('hypothesis', {}).get('attack_scenario', 'No generada')}

Genera el reporte en JSON:
{{
    "executive_summary": "Resumen ejecutivo de 3-4 oraciones para un CISO",
    "threat_level": "CRÍTICO/ALTO/MEDIO/BAJO",
    "key_findings": ["Hallazgo 1", "Hallazgo 2", "Hallazgo 3"],
    "attribution": "Atribución o 'No determinado'",
    "immediate_actions": ["Acción 1", "Acción 2"],
    "long_term_recommendations": ["Recomendación 1", "Recomendación 2"],
    "iocs_to_block": ["IOC1", "IOC2"],
    "confidence_assessment": "Evaluación de la confianza en estos hallazgos"
}}"""

        try:
            response = self.llm_service._call_generic_openai_style(prompt)
            
            if isinstance(response, dict):
                text = response.get('analysis') or response.get('content') or ''
            else:
                text = str(response)
            
            json_match = re.search(r'\{.*\}', text, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group(0))
                except json.JSONDecodeError:
                    pass
            
            return {
                'executive_summary': text,
                'threat_level': all_results.get('base_analysis', {}).get('risk_level', 'MEDIO'),
                'key_findings': [],
                'attribution': all_results.get('apt_analysis', {}).get('identified_apt', 'No determinado')
            }
            
        except Exception as e:
            logger.error(f"Report generation error: {e}")
            return {
                'executive_summary': f'Error generando reporte: {str(e)}',
                'threat_level': 'DESCONOCIDO'
            }
