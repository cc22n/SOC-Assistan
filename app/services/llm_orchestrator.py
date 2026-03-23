"""
LLM Orchestrator - Sistema inteligente de análisis
v6: Deep Analysis + Re-consulta inteligente

CAMBIOS v6 (Febrero 2025):
- NUEVO: Deep Analysis integrado (búsqueda web OSINT, correlación, APT, hipótesis)
- Detecta frases como "analiza profundamente", "investigación profunda"
- 4 módulos de análisis profundo: Web OSINT, Correlación, APT, Hipótesis
- Mantiene todas las funcionalidades de v5 (17 APIs, re-consulta inteligente)
"""
import json
import logging
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from flask import current_app

logger = logging.getLogger(__name__)


class LLMOrchestrator:
    """
    Sistema inteligente con re-consulta automática.

    Flujo mejorado:
    1. Usuario hace pregunta
    2. Sistema detecta si necesita datos adicionales
    3. Si faltan datos → consulta APIs automáticamente
    4. Responde con información completa
    """

    def __init__(self):
        self.llm_providers = {
            'xai': self._get_xai_client,
            'openai': self._get_openai_client,
            'groq': self._get_groq_client,
            'gemini': self._get_gemini_client
        }

        self.api_clients = {}
        self._clients_initialized = False
        self._session_manager = None
        self._deep_analysis_service = None

        # Keywords para activar Deep Analysis (NUEVO v6)
        self.deep_analysis_keywords = [
            'analiza profundamente', 'análisis profundo', 'investigación profunda',
            'deep analysis', 'análisis completo', 'investiga a fondo',
            'analiza en profundidad', 'investigar a fondo', 'análisis exhaustivo',
            'investigación completa', 'analizar profundamente', 'análisis detallado',
            'investigación exhaustiva', 'analisis profundo', 'investiga profundamente'
        ]

        # Estrategias por tipo de IOC (ACTUALIZADO sin censys/ipqualityscore)
        self.strategies = {
            'ip': ['greynoise', 'abuseipdb', 'shodan', 'criminal_ip', 'pulsedive', 'otx'],
            'domain': ['urlhaus', 'otx', 'securitytrails', 'virustotal', 'google_safebrowsing', 'urlscan'],
            'url': ['urlhaus', 'google_safebrowsing', 'virustotal', 'urlscan', 'pulsedive'],
            'hash': ['virustotal', 'threatfox', 'hybrid_analysis', 'malwarebazaar', 'otx', 'pulsedive']
        }

        # Mapeo de qué pregunta necesita qué API (ACTUALIZADO)
        self.question_to_api_mapping = {
            # Preguntas sobre puertos/servicios
            'puertos': ['shodan', 'shodan_internetdb', 'criminal_ip'],
            'servicios': ['shodan', 'shodan_internetdb', 'criminal_ip'],
            'ports': ['shodan', 'shodan_internetdb', 'criminal_ip'],
            'abiertos': ['shodan', 'shodan_internetdb'],

            # Preguntas sobre C2/malware
            'c2': ['threatfox', 'otx', 'urlhaus', 'pulsedive'],
            'comando y control': ['threatfox', 'otx', 'pulsedive'],
            'botnet': ['threatfox', 'otx', 'abuseipdb', 'criminal_ip'],
            'malware': ['virustotal', 'hybrid_analysis', 'threatfox', 'malwarebazaar'],
            'ransomware': ['virustotal', 'hybrid_analysis', 'threatfox', 'malwarebazaar'],

            # Preguntas sobre reputación
            'reputación': ['abuseipdb', 'greynoise', 'criminal_ip', 'pulsedive'],
            'reputation': ['abuseipdb', 'greynoise', 'criminal_ip', 'pulsedive'],
            'malicioso': ['virustotal', 'abuseipdb', 'greynoise', 'criminal_ip'],
            'peligroso': ['virustotal', 'abuseipdb', 'greynoise', 'criminal_ip'],
            'confiable': ['abuseipdb', 'greynoise', 'criminal_ip'],

            # Preguntas sobre DNS/dominio
            'dns': ['securitytrails', 'otx'],
            'whois': ['securitytrails'],
            'registrado': ['securitytrails'],
            'historial': ['securitytrails', 'otx'],
            'subdominio': ['securitytrails'],

            # Preguntas sobre phishing
            'phishing': ['google_safebrowsing', 'urlhaus', 'virustotal', 'urlscan', 'criminal_ip'],
            'fraude': ['google_safebrowsing', 'criminal_ip', 'pulsedive'],
            'scam': ['google_safebrowsing', 'criminal_ip', 'pulsedive'],

            # Preguntas sobre geolocalización
            'ubicación': ['shodan', 'ip_api', 'abuseipdb', 'criminal_ip'],
            'país': ['shodan', 'ip_api', 'abuseipdb'],
            'geolocalización': ['ip_api', 'shodan', 'criminal_ip'],
            'location': ['ip_api', 'shodan', 'criminal_ip'],

            # Preguntas sobre sandbox/comportamiento
            'comportamiento': ['hybrid_analysis'],
            'sandbox': ['hybrid_analysis'],
            'ejecución': ['hybrid_analysis'],
            'análisis dinámico': ['hybrid_analysis'],

            # Preguntas sobre certificados SSL
            'certificado': ['shodan', 'criminal_ip'],
            'ssl': ['shodan', 'criminal_ip'],
            'https': ['shodan', 'criminal_ip'],

            # Preguntas sobre proxies/VPN/Tor
            'proxy': ['criminal_ip', 'greynoise', 'ip_api'],
            'vpn': ['criminal_ip', 'greynoise', 'ip_api'],
            'tor': ['criminal_ip', 'greynoise', 'abuseipdb'],
            'anonimato': ['criminal_ip', 'greynoise'],

            # Preguntas sobre screenshots/visual
            'screenshot': ['urlscan'],
            'captura': ['urlscan'],
            'visual': ['urlscan'],
        }

        try:
            self._initialize_clients()
        except:
            pass

    @property
    def session_manager(self):
        if self._session_manager is None:
            from app.services.session_manager import SessionManager
            self._session_manager = SessionManager()
        return self._session_manager

    @property
    def deep_analysis_service(self):
        """Servicio de análisis profundo (NUEVO v6)"""
        if self._deep_analysis_service is None:
            from app.services.deep_analysis_service import DeepAnalysisService
            self._deep_analysis_service = DeepAnalysisService()
        return self._deep_analysis_service

    def _initialize_clients(self):
        """Inicializa los clientes de API (ACTUALIZADO v5)"""
        if self._clients_initialized:
            return

        try:
            from flask import current_app
            if not current_app:
                return

            # Importar TODOS los clientes de new_api_clients (unificado v3)
            from app.services.new_api_clients import (
                VirusTotalClient, AbuseIPDBClient, ShodanClient, OTXClient,
                GreyNoiseClient, URLhausClient, ThreatFoxClient,
                GoogleSafeBrowsingClient, SecurityTrailsClient, HybridAnalysisClient,
                MalwareBazaarClient, CriminalIPClient, PulsediveClient,
                URLScanClient, ShodanInternetDBClient, IPAPIClient,
                CensysClient, IPinfoClient
            )

            self.api_clients = {
                # APIs Principales
                'virustotal': VirusTotalClient(),
                'abuseipdb': AbuseIPDBClient(),
                'shodan': ShodanClient(),
                'otx': OTXClient(),
                'greynoise': GreyNoiseClient(),

                # APIs abuse.ch
                'urlhaus': URLhausClient(),
                'threatfox': ThreatFoxClient(),
                'malwarebazaar': MalwareBazaarClient(),  # NUEVO

                # Otras APIs
                'google_safebrowsing': GoogleSafeBrowsingClient(),
                'securitytrails': SecurityTrailsClient(),
                'hybrid_analysis': HybridAnalysisClient(),

                # NUEVAS APIs v3
                'criminal_ip': CriminalIPClient(),
                'pulsedive': PulsediveClient(),
                'urlscan': URLScanClient(),
                'shodan_internetdb': ShodanInternetDBClient(),
                'ip_api': IPAPIClient(),

                # APIs v3.1
                'censys': CensysClient(),
                'ipinfo': IPinfoClient(),
            }

            self._clients_initialized = True
            logger.info(f"Initialized {len(self.api_clients)} API clients")

        except Exception as e:
            logger.error(f"Error initializing API clients: {e}")
            self._clients_initialized = False

    # =========================================================================
    # LLM PROVIDERS
    # =========================================================================

    def _get_xai_client(self):
        from app.services.llm_service import LLMService
        return LLMService(provider='xai')

    def _get_openai_client(self):
        from app.services.llm_service import LLMService
        return LLMService(provider='openai')

    def _get_groq_client(self):
        from app.services.llm_service import LLMService
        return LLMService(provider='groq')

    def _get_gemini_client(self):
        from app.services.llm_service import LLMService
        return LLMService(provider='gemini')

    def _get_available_llm(self, specific_provider: str = None) -> Optional[object]:
        api_keys = current_app.config.get('API_KEYS', {})

        if specific_provider and api_keys.get(specific_provider):
            if specific_provider in self.llm_providers:
                try:
                    return self.llm_providers[specific_provider]()
                except Exception as e:
                    logger.warning(f"Failed to initialize {specific_provider}: {e}")

        for provider in ['xai', 'openai', 'groq', 'gemini']:
            if api_keys.get(provider):
                try:
                    return self.llm_providers[provider]()
                except Exception as e:
                    logger.warning(f"Failed to initialize {provider}: {e}")
                    continue
        return None

    def _call_llm(self, llm, prompt: str) -> Dict:
        try:
            if llm.provider == 'gemini':
                return llm._call_gemini(prompt)
            else:
                return llm._call_generic_openai_style(prompt)
        except Exception as e:
            logger.error(f"LLM call error ({llm.provider}): {e}")
            return {'error': str(e)}

    # =========================================================================
    # DETECCIÓN DE NECESIDAD DE RE-CONSULTA
    # =========================================================================

    def _detect_needed_apis(self, question: str, existing_apis: List[str], ioc_type: str) -> List[str]:
        """
        Detecta qué APIs adicionales se necesitan basándose en la pregunta.
        """
        question_lower = question.lower()
        needed_apis = set()

        for keyword, apis in self.question_to_api_mapping.items():
            if keyword in question_lower:
                for api in apis:
                    if api not in existing_apis:
                        if self._is_api_compatible(api, ioc_type):
                            needed_apis.add(api)

        return list(needed_apis)

    def _is_api_compatible(self, api_name: str, ioc_type: str) -> bool:
        """Verifica si una API es compatible con un tipo de IOC (ACTUALIZADO v5)"""
        compatibility = {
            # APIs Principales
            'virustotal': ['ip', 'domain', 'url', 'hash'],
            'abuseipdb': ['ip'],
            'shodan': ['ip'],
            'otx': ['ip', 'domain', 'hash'],
            'greynoise': ['ip'],

            # APIs abuse.ch
            'urlhaus': ['url', 'domain', 'ip'],
            'threatfox': ['ip', 'domain', 'url', 'hash'],
            'malwarebazaar': ['hash'],

            # Otras APIs
            'google_safebrowsing': ['url', 'domain'],
            'securitytrails': ['domain'],
            'hybrid_analysis': ['hash'],

            # Nuevas APIs v3
            'criminal_ip': ['ip', 'domain'],
            'pulsedive': ['ip', 'domain', 'url', 'hash'],
            'urlscan': ['url', 'domain'],
            'shodan_internetdb': ['ip'],
            'ip_api': ['ip'],
            'censys': ['ip'],
            'ipinfo': ['ip'],
        }

        return ioc_type in compatibility.get(api_name, [])

    def _get_session_ioc_data(self, session_id: int, ioc_value: str = None) -> Tuple[
        Optional[str], Optional[str], Dict]:
        """
        Obtiene datos de un IOC de la sesión.
        """
        try:
            session_iocs = self.session_manager.get_session_iocs(session_id)

            # Lista de APIs disponibles (ACTUALIZADO v5)
            available_apis = [
                'virustotal', 'abuseipdb', 'shodan', 'otx', 'greynoise',
                'threatfox', 'urlhaus', 'malwarebazaar',
                'google_safebrowsing', 'securitytrails', 'hybrid_analysis',
                'criminal_ip', 'pulsedive', 'urlscan', 'shodan_internetdb', 'ip_api'
            ]

            for sioc in session_iocs:
                if ioc_value and sioc.ioc and sioc.ioc.value == ioc_value:
                    api_results = {}
                    if sioc.analysis:
                        for api_name in available_apis:
                            data = getattr(sioc.analysis, f'{api_name}_data', None)
                            if data and 'error' not in data:
                                api_results[api_name] = data

                    return sioc.ioc.value, sioc.ioc.ioc_type, api_results

            if session_iocs and not ioc_value:
                last_ioc = session_iocs[-1]
                if last_ioc.ioc:
                    api_results = {}
                    if last_ioc.analysis:
                        for api_name in available_apis:
                            data = getattr(last_ioc.analysis, f'{api_name}_data', None)
                            if data and 'error' not in data:
                                api_results[api_name] = data

                    return last_ioc.ioc.value, last_ioc.ioc.ioc_type, api_results

            return None, None, {}

        except Exception as e:
            logger.error(f"Error getting session IOC data: {e}")
            return None, None, {}

    # =========================================================================
    # ANÁLISIS CON INTELIGENCIA
    # =========================================================================

    def analyze_with_intelligence(
            self,
            ioc: str,
            ioc_type: str,
            user_context: str = "",
            use_llm_planning: bool = True,
            session_context: str = None
    ) -> Dict:
        """Análisis inteligente multi-etapa"""
        self._initialize_clients()
        start_time = datetime.utcnow()

        full_context = user_context
        if session_context:
            full_context = f"{session_context}\n\nConsulta actual: {user_context}"

        if use_llm_planning:
            selected_apis = self._plan_analysis_with_llm(ioc, ioc_type, full_context)
        else:
            selected_apis = self.strategies.get(ioc_type, [])

        logger.info(f"Selected APIs for {ioc_type}: {selected_apis}")

        api_results = self._execute_apis(ioc, ioc_type, selected_apis)
        llm_analysis = self._synthesize_with_llm(ioc, ioc_type, api_results, full_context)
        mitre_techniques = self._correlate_mitre(api_results, llm_analysis)
        confidence_score = self._calculate_enhanced_score(api_results, llm_analysis)
        risk_level = self._determine_risk_level(confidence_score)

        processing_time = (datetime.utcnow() - start_time).total_seconds()

        return {
            'ioc': ioc,
            'type': ioc_type,
            'confidence_score': confidence_score,
            'risk_level': risk_level,
            'api_results': api_results,
            'llm_analysis': llm_analysis,
            'mitre_techniques': mitre_techniques,
            'sources_used': list(api_results.keys()),
            'selected_apis': selected_apis,
            'processing_time': processing_time,
            'timestamp': datetime.utcnow().isoformat()
        }

    def _plan_analysis_with_llm(self, ioc: str, ioc_type: str, user_context: str) -> List[str]:
        llm = self._get_available_llm()
        if not llm:
            return self.strategies.get(ioc_type, [])

        available_apis = list(self.api_clients.keys())
        prompt = f"""Eres un experto analista SOC. Decide qué APIs usar para analizar este IOC.

IOC: {ioc} ({ioc_type})
Contexto: {user_context}
APIs disponibles: {json.dumps(available_apis)}

Selecciona las APIs más relevantes (máximo 6).
Responde SOLO con un array JSON: ["api1", "api2", ...]"""

        try:
            response = self._call_llm(llm, prompt)

            if isinstance(response, dict):
                text = response.get('analysis') or response.get('content') or json.dumps(response)
            else:
                text = str(response)

            match = re.search(r'\[.*?\]', text, re.DOTALL)
            if match:
                apis = json.loads(match.group(0))
                valid_apis = [api for api in apis if api in available_apis]
                return valid_apis[:6] if valid_apis else self.strategies.get(ioc_type, [])

        except Exception as e:
            logger.error(f"LLM planning error: {e}")

        return self.strategies.get(ioc_type, [])

    def _execute_apis(self, ioc: str, ioc_type: str, selected_apis: List[str]) -> Dict:
        """
        Ejecuta las APIs seleccionadas EN PARALELO (v2 - async).

        Usa asyncio + ThreadPoolExecutor para ejecutar todas las APIs
        simultaneamente. ~19s -> ~3s para analisis completo.
        """
        from app.services.async_executor import execute_apis_parallel

        return execute_apis_parallel(
            ioc=ioc,
            ioc_type=ioc_type,
            selected_apis=selected_apis,
            api_clients=self.api_clients,
            timeout_per_api=30.0
        )

    def _execute_additional_apis(self, ioc: str, ioc_type: str, apis_to_call: List[str],
                                 existing_results: Dict) -> Dict:
        """Ejecuta APIs adicionales y combina con resultados existentes"""
        new_results = self._execute_apis(ioc, ioc_type, apis_to_call)

        combined = existing_results.copy()
        combined.update(new_results)

        return combined, new_results

    def _synthesize_with_llm(self, ioc: str, ioc_type: str, api_results: Dict, user_context: str) -> Dict:
        llm = self._get_available_llm()
        if not llm:
            return self._fallback_synthesis(api_results)

        clean_results = {k: v for k, v in api_results.items() if 'error' not in v}

        prompt = f"""Eres un analista SOC experto. Analiza estos resultados de threat intelligence:

IOC: {ioc} (Tipo: {ioc_type})
Contexto: {user_context}

Resultados de APIs:
{json.dumps(clean_results, indent=2, default=str)}

Genera un análisis JSON con estas claves exactas:
{{
    "executive_summary": "Resumen ejecutivo de 2-3 oraciones",
    "threat_level": "CRÍTICO/ALTO/MEDIO/BAJO/LIMPIO",
    "key_findings": ["hallazgo 1", "hallazgo 2"],
    "indicators": ["indicador técnico 1", "indicador 2"],
    "recommendations": ["acción 1", "acción 2", "acción 3"],
    "confidence_reasoning": "Por qué este nivel de confianza"
}}

Responde SOLO con el JSON."""

        try:
            response = self._call_llm(llm, prompt)

            if isinstance(response, dict):
                if any(k in response for k in ['executive_summary', 'threat_level', 'key_findings']):
                    return response
                if 'analysis' in response:
                    text = response['analysis']
                    match = re.search(r'\{.*\}', text, re.DOTALL)
                    if match:
                        return json.loads(match.group(0))

            return self._fallback_synthesis(api_results)

        except Exception as e:
            logger.error(f"Synthesis error: {e}")
            return self._fallback_synthesis(api_results)

    def _fallback_synthesis(self, api_results: Dict) -> Dict:
        successful = sum(1 for v in api_results.values() if 'error' not in v)
        return {
            'executive_summary': f"Análisis completado. {successful} fuentes consultadas.",
            'threat_level': 'MEDIO',
            'key_findings': [f"Se consultaron {len(api_results)} fuentes"],
            'indicators': list(api_results.keys()),
            'recommendations': ["Revisar resultados detallados", "Correlacionar con logs internos"],
            'confidence_reasoning': 'Análisis automático'
        }

    def _correlate_mitre(self, api_results: Dict, llm_analysis: Dict) -> List[str]:
        techniques = []
        if 'shodan' in api_results and 'error' not in api_results.get('shodan', {}):
            techniques.append('T1046')
        if 'threatfox' in api_results and 'error' not in api_results.get('threatfox', {}):
            techniques.extend(['T1071', 'T1095'])
        if api_results.get('greynoise', {}).get('classification') == 'malicious':
            techniques.append('T1595')
        if api_results.get('hybrid_analysis', {}).get('verdict') == 'malicious':
            techniques.extend(['T1204', 'T1059'])
        if api_results.get('criminal_ip', {}).get('is_scanner'):
            techniques.append('T1595.001')
        if api_results.get('pulsedive', {}).get('risk') == 'high':
            techniques.append('T1583')
        return list(set(techniques))

    def _calculate_enhanced_score(self, api_results: Dict, llm_analysis: Dict) -> int:
        """Calcula score de riesgo (ACTUALIZADO v5 con nuevas APIs)"""
        score = 0
        for api_name, result in api_results.items():
            if 'error' not in result:
                score += 5

                if api_name == 'virustotal':
                    # VT v3 usa 'malicious' en vez de 'positive_detections'
                    detections = result.get('malicious', result.get('positive_detections', 0))
                    if detections and detections > 0:
                        score += min(30, detections * 2)
                elif api_name == 'greynoise':
                    if result.get('classification') == 'malicious':
                        score += 25
                elif api_name == 'abuseipdb':
                    score += int(result.get('abuse_confidence', result.get('abuse_confidence_score', 0)) * 0.3)
                elif api_name == 'threatfox':
                    if result.get('threat_type') or result.get('found'):
                        score += 30
                elif api_name == 'hybrid_analysis':
                    if result.get('verdict') == 'malicious':
                        score += 25
                elif api_name == 'urlhaus':
                    if result.get('url_status') == 'online' or result.get('found'):
                        score += 20
                elif api_name == 'google_safebrowsing':
                    if result.get('is_malicious'):
                        score += 25
                elif api_name == 'malwarebazaar':
                    if result.get('found'):
                        score += 25
                # Nuevas APIs v3
                elif api_name == 'criminal_ip':
                    if result.get('is_malicious'):
                        score += 25
                    elif result.get('is_scanner') or result.get('is_tor'):
                        score += 15
                elif api_name == 'pulsedive':
                    risk = result.get('risk', '').lower()
                    if risk == 'high':
                        score += 25
                    elif risk == 'medium':
                        score += 15
                elif api_name == 'urlscan':
                    verdicts = result.get('verdicts', {})
                    if verdicts.get('malicious'):
                        score += 20

        return min(100, score)

    def _determine_risk_level(self, score: int) -> str:
        if score >= 70: return 'CRÍTICO'
        if score >= 50: return 'ALTO'
        if score >= 30: return 'MEDIO'
        if score >= 10: return 'BAJO'
        return 'LIMPIO'

    # =========================================================================
    # CHAT CON SESIONES Y RE-CONSULTA INTELIGENTE
    # =========================================================================

    def chat_analysis(
            self,
            message: str,
            user_id: int = None,
            session_id: int = None,
            conversation_history: List[Dict] = None,
            preferred_provider: str = None
    ) -> Dict:
        """
        Análisis conversacional con re-consulta inteligente.

        Si el usuario pregunta algo que requiere datos que no tenemos,
        automáticamente consulta las APIs necesarias.
        """
        self._initialize_clients()

        llm = self._get_available_llm(specific_provider=preferred_provider)

        if not llm:
            return {
                'response': 'LLM no disponible. Configure una API key en .env',
                'requires_analysis': False,
                'session_id': None
            }

        # =====================================================================
        # GESTIÓN DE SESIÓN
        # =====================================================================

        session = None
        session_context = ""

        if user_id:
            try:
                if session_id:
                    session = self.session_manager.get_session(session_id)

                if not session:
                    session, is_new = self.session_manager.get_or_create_session(user_id)
                    if is_new:
                        logger.info(f"Created new session {session.id} for user {user_id}")

                if session:
                    session_context = self.session_manager.build_context_for_llm(session.id)

            except Exception as e:
                logger.error(f"Session management error: {e}")

        # =====================================================================
        # DETECCIÓN DE DEEP ANALYSIS (NUEVO v6)
        # =====================================================================

        if self._is_deep_analysis_request(message):
            ioc_match = self._extract_ioc_from_message(message)
            if ioc_match:
                ioc_value, ioc_type = ioc_match
                logger.info(f"🔍 Deep analysis triggered for {ioc_type}: {ioc_value}")
                return self._handle_deep_analysis_request(
                    llm=llm,
                    ioc=ioc_value,
                    ioc_type=ioc_type,
                    message=message,
                    session=session,
                    session_context=session_context,
                    user_id=user_id
                )

        # =====================================================================
        # DETECCIÓN DE INTENCIÓN MEJORADA
        # =====================================================================

        intent_prompt = f"""{session_context if session_context else ""}

Analiza este mensaje del usuario y determina qué necesita.

Mensaje: "{message}"

Responde en JSON con este formato exacto:
{{
    "intent_type": "new_ioc_analysis" | "question_about_previous" | "general_question",
    "has_ioc": true/false,
    "ioc_value": "valor del IOC o null",
    "ioc_type": "ip/domain/url/hash o null",
    "references_previous_ioc": true/false,
    "question_topic": "puertos/malware/reputación/dns/c2/ubicación/etc o null",
    "user_question": "resumen de qué quiere saber"
}}

IMPORTANTE:
- Si el usuario pregunta sobre "el hash", "la IP anterior", "ese dominio", etc., es "question_about_previous"
- Si pregunta por puertos, servicios, C2, malware, etc., indica el topic en "question_topic"
- Si menciona un IOC nuevo explícitamente, es "new_ioc_analysis"
"""

        try:
            raw_response = self._call_llm(llm, intent_prompt)

            # Parsing robusto
            intent = {}
            json_str = ""

            if isinstance(raw_response, dict):
                json_str = raw_response.get('analysis') or raw_response.get('content') or ""
                if 'intent_type' in raw_response:
                    intent = raw_response
            elif isinstance(raw_response, str):
                json_str = raw_response

            if not intent:
                json_match = re.search(r'\{.*\}', json_str, re.DOTALL)
                if json_match:
                    try:
                        intent = json.loads(json_match.group(0))
                    except json.JSONDecodeError:
                        logger.warning(f"JSON inválido en intent: {json_str}")
                        intent = {'intent_type': 'general_question'}

            logger.info(f"Detected intent: {intent.get('intent_type')} - topic: {intent.get('question_topic')}")

            # =================================================================
            # GUARDAR MENSAJE DEL USUARIO
            # =================================================================

            user_message_id = None
            if session:
                try:
                    user_msg = self.session_manager.save_message(
                        session_id=session.id,
                        role='user',
                        content=message,
                        iocs_mentioned=[intent.get('ioc_value')] if intent.get('has_ioc') else None
                    )
                    user_message_id = user_msg.id
                except Exception as e:
                    logger.error(f"Error saving user message: {e}")

            # =================================================================
            # PROCESAR SEGÚN TIPO DE INTENCIÓN
            # =================================================================

            intent_type = intent.get('intent_type', 'general_question')

            # -----------------------------------------------------------------
            # CASO 1: Nuevo IOC para analizar
            # -----------------------------------------------------------------
            if intent_type == 'new_ioc_analysis' and intent.get('ioc_value'):
                return self._handle_new_ioc_analysis(
                    llm, intent, message, session, session_context, user_id, user_message_id
                )

            # -----------------------------------------------------------------
            # CASO 2: Pregunta sobre IOC previo
            # -----------------------------------------------------------------
            elif intent_type == 'question_about_previous' or intent.get('references_previous_ioc'):
                return self._handle_question_about_previous(
                    llm, intent, message, session, session_context
                )

            # -----------------------------------------------------------------
            # CASO 3: Pregunta general
            # -----------------------------------------------------------------
            else:
                return self._handle_general_question(llm, message, session, session_context)

        except Exception as e:
            logger.error(f"Chat analysis error: {e}")
            return {
                'response': f"Error procesando solicitud: {str(e)}",
                'requires_analysis': False,
                'session_id': session.id if session else None
            }

    def _handle_new_ioc_analysis(self, llm, intent, message, session, session_context, user_id, user_message_id):
        """Maneja análisis de un IOC nuevo"""
        ioc = intent['ioc_value']
        ioc_type = intent.get('ioc_type') or self._detect_ioc_type(ioc)

        analysis = self.analyze_with_intelligence(
            ioc=ioc,
            ioc_type=ioc_type,
            user_context=message,
            session_context=session_context
        )

        if session:
            analysis_obj = self._save_analysis_to_session(
                session, ioc, ioc_type, analysis, user_id, user_message_id
            )
        else:
            analysis_obj = None

        response_text = self._generate_analysis_response(
            llm, ioc, ioc_type, analysis, message, session_context
        )

        if session:
            self._save_assistant_message(session, response_text, True, analysis_obj, llm.provider)

        return {
            'response': response_text,
            'requires_analysis': True,
            'analysis_data': {
                'ioc': ioc,
                'type': ioc_type,
                'confidence_score': analysis['confidence_score'],
                'risk_level': analysis['risk_level'],
                'sources_used': analysis['sources_used']
            },
            'session_id': session.id if session else None,
            'session_title': session.title if session else None,
            'llm_provider': llm.provider
        }

    def _handle_question_about_previous(self, llm, intent, message, session, session_context):
        """
        Maneja preguntas sobre IOCs previamente analizados.
        Incluye RE-CONSULTA INTELIGENTE si faltan datos.
        """
        if not session:
            return self._handle_general_question(llm, message, session, session_context)

        ioc_mentioned = intent.get('ioc_value')
        question_topic = intent.get('question_topic')

        ioc_value, ioc_type, existing_api_data = self._get_session_ioc_data(
            session.id, ioc_mentioned
        )

        if not ioc_value:
            return self._handle_general_question(llm, message, session, session_context)

        # RE-CONSULTA INTELIGENTE
        additional_data = {}
        if question_topic:
            needed_apis = self._detect_needed_apis(
                message, list(existing_api_data.keys()), ioc_type
            )

            if needed_apis:
                logger.info(f"Re-querying APIs for {ioc_value}: {needed_apis}")
                _, additional_data = self._execute_additional_apis(
                    ioc_value, ioc_type, needed_apis, existing_api_data
                )

                if additional_data:
                    self._update_session_analysis(session.id, ioc_value, additional_data)

        all_api_data = {**existing_api_data, **additional_data}

        response_prompt = f"""Eres un analista SOC experto.

{session_context if session_context else ""}

El usuario está investigando el IOC: {ioc_value} ({ioc_type})

=== DATOS DISPONIBLES DE APIs ===
{json.dumps(all_api_data, indent=2, default=str)}

{"=== DATOS NUEVOS CONSULTADOS AHORA ===" + chr(10) + json.dumps(additional_data, indent=2, default=str) if additional_data else ""}

=== PREGUNTA DEL USUARIO ===
"{message}"

Responde la pregunta del usuario usando los datos disponibles.
- Sé específico y usa los datos reales de las APIs
- Si consultamos APIs adicionales ahora, menciona que obtuviste información nueva
- Si aún no tenemos cierta información, indícalo claramente
- Usa emojis para severidad (🔴 crítico, 🟠 alto, 🟡 medio, 🟢 bajo)
"""

        resp_obj = self._call_llm(llm, response_prompt)

        if isinstance(resp_obj, dict):
            response_text = resp_obj.get('analysis') or resp_obj.get('content') or str(resp_obj)
        else:
            response_text = str(resp_obj)

        # Guardar respuesta
        if session:
            self._save_assistant_message(session, response_text, bool(additional_data), None, llm.provider)

        return {
            'response': response_text,
            'requires_analysis': bool(additional_data),
            'additional_apis_consulted': list(additional_data.keys()) if additional_data else [],
            'session_id': session.id,
            'session_title': session.title,
            'llm_provider': llm.provider
        }

    def _handle_general_question(self, llm, message, session, session_context):
        """Maneja preguntas generales sin IOC específico"""
        if session_context:
            prompt = f"""{session_context}

=== PREGUNTA DEL USUARIO ===
"{message}"

Responde considerando el contexto de la investigación. Sé profesional y útil."""
        else:
            prompt = f"""Eres un analista SOC experto. El usuario pregunta:

"{message}"

Responde de forma clara, profesional y útil."""

        resp_obj = self._call_llm(llm, prompt)

        if isinstance(resp_obj, dict):
            response_text = resp_obj.get('analysis') or resp_obj.get('content') or str(resp_obj)
        else:
            response_text = str(resp_obj)

        if session:
            self._save_assistant_message(session, response_text, False, None, llm.provider)

        return {
            'response': response_text,
            'requires_analysis': False,
            'session_id': session.id if session else None,
            'session_title': session.title if session else None,
            'llm_provider': llm.provider
        }

    # =========================================================================
    # HELPERS
    # =========================================================================

    def _detect_ioc_type(self, ioc: str) -> str:
        """Detecta el tipo de IOC"""
        import re

        # Hash patterns
        if re.match(r'^[a-fA-F0-9]{64}$', ioc):
            return 'hash'  # SHA256
        if re.match(r'^[a-fA-F0-9]{40}$', ioc):
            return 'hash'  # SHA1
        if re.match(r'^[a-fA-F0-9]{32}$', ioc):
            return 'hash'  # MD5

        # IP pattern
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc):
            return 'ip'

        # URL pattern
        if ioc.startswith(('http://', 'https://')):
            return 'url'

        # Domain pattern (default)
        if '.' in ioc and not ioc.replace('.', '').isdigit():
            return 'domain'

        return 'unknown'

    def _save_analysis_to_session(self, session, ioc, ioc_type, analysis, user_id, user_message_id):
        """Guarda el análisis en BD y lo vincula a la sesión (ACTUALIZADO v5)"""
        try:
            from app.models.ioc import IOC, IOCAnalysis
            from app import db

            ioc_obj = IOC.query.filter_by(value=ioc, ioc_type=ioc_type).first()
            if not ioc_obj:
                ioc_obj = IOC(value=ioc, ioc_type=ioc_type)
                db.session.add(ioc_obj)
                db.session.flush()

            # Crear análisis con todos los campos de APIs disponibles
            analysis_obj = IOCAnalysis(
                ioc_id=ioc_obj.id,
                user_id=user_id,
                confidence_score=analysis['confidence_score'],
                risk_level=analysis['risk_level'],

                # APIs Principales
                virustotal_data=analysis['api_results'].get('virustotal'),
                abuseipdb_data=analysis['api_results'].get('abuseipdb'),
                shodan_data=analysis['api_results'].get('shodan'),
                otx_data=analysis['api_results'].get('otx'),
                greynoise_data=analysis['api_results'].get('greynoise'),

                # APIs abuse.ch
                threatfox_data=analysis['api_results'].get('threatfox'),
                urlhaus_data=analysis['api_results'].get('urlhaus'),
                malwarebazaar_data=analysis['api_results'].get('malwarebazaar'),

                # Otras APIs
                google_safebrowsing_data=analysis['api_results'].get('google_safebrowsing'),
                securitytrails_data=analysis['api_results'].get('securitytrails'),
                hybrid_analysis_data=analysis['api_results'].get('hybrid_analysis'),

                # Nuevas APIs v3
                criminal_ip_data=analysis['api_results'].get('criminal_ip'),
                pulsedive_data=analysis['api_results'].get('pulsedive'),
                urlscan_data=analysis['api_results'].get('urlscan'),
                shodan_internetdb_data=analysis['api_results'].get('shodan_internetdb'),
                ip_api_data=analysis['api_results'].get('ip_api'),

                # LLM y metadata
                llm_analysis=analysis.get('llm_analysis'),
                mitre_techniques=analysis.get('mitre_techniques', []),
                sources_used=analysis.get('sources_used', []),
                processing_time=analysis['processing_time']
            )
            db.session.add(analysis_obj)
            db.session.flush()

            self.session_manager.add_ioc_to_session(
                session_id=session.id,
                ioc_id=ioc_obj.id,
                analysis_id=analysis_obj.id,
                role='analyzed',
                message_id=user_message_id
            )

            db.session.commit()
            return analysis_obj

        except Exception as e:
            logger.error(f"Error saving analysis to session: {e}")
            from app import db
            db.session.rollback()
            return None

    def _update_session_analysis(self, session_id: int, ioc_value: str, new_api_data: Dict):
        """Actualiza un análisis existente con datos de APIs adicionales"""
        try:
            from app import db

            session_iocs = self.session_manager.get_session_iocs(session_id)

            for sioc in session_iocs:
                if sioc.ioc and sioc.ioc.value == ioc_value and sioc.analysis:
                    for api_name, data in new_api_data.items():
                        if 'error' not in data:
                            setattr(sioc.analysis, f'{api_name}_data', data)
                            if sioc.analysis.sources_used:
                                if api_name not in sioc.analysis.sources_used:
                                    sioc.analysis.sources_used = sioc.analysis.sources_used + [api_name]
                            else:
                                sioc.analysis.sources_used = [api_name]

                    db.session.commit()
                    logger.info(f"Updated analysis for {ioc_value} with new APIs: {list(new_api_data.keys())}")
                    break

        except Exception as e:
            logger.error(f"Error updating session analysis: {e}")

    def _generate_analysis_response(self, llm, ioc, ioc_type, analysis, message, session_context):
        """Genera respuesta conversacional para un análisis"""
        response_prompt = f"""Eres un analista SOC experto.

{"=== CONTEXTO ===" + chr(10) + session_context if session_context else ""}

El usuario preguntó: "{message}"

Resultados del análisis de {ioc} ({ioc_type}):
{json.dumps(analysis, indent=2, default=str)}

Genera una respuesta que incluya:
1. Resumen del hallazgo (¿malicioso o no?)
2. Datos clave de las fuentes
3. Nivel de riesgo
4. 2-3 acciones recomendadas

Usa emojis para severidad (🔴🟠🟡🟢)."""

        resp_obj = self._call_llm(llm, response_prompt)

        if isinstance(resp_obj, dict):
            return resp_obj.get('analysis') or resp_obj.get('content') or str(resp_obj)
        return str(resp_obj)

    def _save_assistant_message(self, session, content, analysis_triggered, analysis_obj, provider):
        """Guarda mensaje del asistente en la sesión"""
        try:
            self.session_manager.save_message(
                session_id=session.id,
                role='assistant',
                content=content,
                analysis_triggered=analysis_triggered,
                analysis_id=analysis_obj.id if analysis_obj else None,
                llm_provider=provider
            )
        except Exception as e:
            logger.error(f"Error saving assistant message: {e}")

    # =========================================================================
    # MÉTODOS DE SESIÓN (WRAPPER)
    # =========================================================================

    def get_session_context(self, session_id: int) -> str:
        return self.session_manager.build_context_for_llm(session_id)

    def get_session_summary(self, session_id: int) -> Dict:
        return self.session_manager.get_session_summary_for_ui(session_id)

    # =========================================================================
    # DEEP ANALYSIS (NUEVO v6)
    # =========================================================================

    def _is_deep_analysis_request(self, message: str) -> bool:
        """Detecta si el usuario solicita análisis profundo"""
        message_lower = message.lower()
        return any(kw in message_lower for kw in self.deep_analysis_keywords)

    def _extract_ioc_from_message(self, message: str) -> Optional[Tuple[str, str]]:
        """Extrae IOC del mensaje"""
        # IP
        ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', message)
        if ip_match:
            return ip_match.group(1), 'ip'

        # Hash SHA256
        sha256_match = re.search(r'\b([a-fA-F0-9]{64})\b', message)
        if sha256_match:
            return sha256_match.group(1), 'hash'

        # Hash SHA1
        sha1_match = re.search(r'\b([a-fA-F0-9]{40})\b', message)
        if sha1_match:
            return sha1_match.group(1), 'hash'

        # Hash MD5
        md5_match = re.search(r'\b([a-fA-F0-9]{32})\b', message)
        if md5_match:
            return md5_match.group(1), 'hash'

        # URL
        url_match = re.search(r'(https?://[^\s]+)', message)
        if url_match:
            return url_match.group(1), 'url'

        # Domain (básico)
        domain_match = re.search(r'\b([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)\b', message)
        if domain_match:
            domain = domain_match.group(1)
            # Evitar falsos positivos
            if domain not in ['analiza.profundamente', 'investigación.profunda']:
                return domain, 'domain'

        return None

    def _handle_deep_analysis_request(
            self,
            llm,
            ioc: str,
            ioc_type: str,
            message: str,
            session,
            session_context: str,
            user_id: int
    ) -> Dict:
        """
        Maneja solicitudes de análisis profundo.
        Ejecuta: APIs + Web Search + Correlación + APT + Hipótesis
        """
        logger.info(f"🔍 Starting deep analysis for {ioc}")

        try:
            # Ejecutar análisis profundo
            deep_result = self.deep_analysis_service.deep_analyze(
                ioc=ioc,
                ioc_type=ioc_type,
                user_id=user_id,
                session_id=session.id if session else None,
                include_web_search=True,
                include_correlation=True,
                include_apt_analysis=True,
                include_hypothesis=True
            )

            # Formatear respuesta
            response_text = self._format_deep_analysis_response(deep_result, ioc)

            # Guardar en sesión
            if session:
                self._save_assistant_message(session, response_text, True, None, llm.provider)

            return {
                'response': response_text,
                'requires_analysis': True,
                'deep_analysis': True,
                'analysis_data': {
                    'ioc': ioc,
                    'type': ioc_type,
                    'threat_level': deep_result.get('base_analysis', {}).get('risk_level', 'N/A'),
                    'apt': deep_result.get('apt_analysis', {}).get('identified_apt'),
                    'modules_executed': deep_result.get('modules_executed', []),
                    'full_result': deep_result
                },
                'session_id': session.id if session else None,
                'session_title': session.title if session else None,
                'llm_provider': llm.provider,
                'processing_time': deep_result.get('processing_time', 0)
            }

        except Exception as e:
            logger.error(f"Deep analysis error: {e}")
            return {
                'response': f"Error en análisis profundo: {str(e)}. Intenta con un análisis normal.",
                'requires_analysis': False,
                'deep_analysis': False,
                'error': str(e),
                'session_id': session.id if session else None,
                'llm_provider': llm.provider
            }

    def _format_deep_analysis_response(self, result: Dict, ioc: str) -> str:
        """Formatea la respuesta del análisis profundo"""
        parts = [f"## 🔍 Análisis Profundo: {ioc}\n"]

        final_report = result.get('final_report', {})
        base_analysis = result.get('base_analysis', {})
        apt_analysis = result.get('apt_analysis', {})
        hypothesis = result.get('hypothesis', {})
        web_search = result.get('web_search', {})
        correlations = result.get('correlations', {})

        # Resumen ejecutivo
        if final_report.get('executive_summary'):
            parts.append(f"**Resumen:** {final_report['executive_summary']}\n")

        # Nivel de amenaza
        threat_level = final_report.get('threat_level', base_analysis.get('risk_level', 'N/A'))
        emoji_map = {'CRÍTICO': '🔴', 'ALTO': '🟠', 'MEDIO': '🟡', 'BAJO': '🟢', 'LIMPIO': '✅'}
        emoji = emoji_map.get(str(threat_level).upper(), '⚪')
        score = base_analysis.get('confidence_score', 'N/A')
        parts.append(f"**Nivel de Riesgo:** {emoji} {threat_level} ({score}%)\n")

        # Hallazgos clave
        if final_report.get('key_findings'):
            parts.append("**Hallazgos Clave:**")
            for finding in final_report['key_findings'][:4]:
                parts.append(f"• {finding}")
            parts.append("")

        # Atribución APT
        if apt_analysis.get('identified_apt'):
            parts.append(f"### 🎯 Atribución")
            parts.append(
                f"**Grupo:** {apt_analysis['identified_apt']} (Confianza: {apt_analysis.get('confidence', 'N/A')})")
            if apt_analysis.get('evidence'):
                parts.append(f"**Evidencia:** {', '.join(apt_analysis['evidence'][:3])}")
            if apt_analysis.get('mitre_techniques'):
                techniques = ', '.join(apt_analysis['mitre_techniques'][:5])
                parts.append(f"**MITRE ATT&CK:** {techniques}")
            parts.append("")
        elif apt_analysis.get('analysis') and len(apt_analysis['analysis']) > 20:
            parts.append(f"### 🎯 Análisis de Atribución")
            parts.append(f"{apt_analysis['analysis'][:400]}")
            parts.append("")

        # Hipótesis de ataque
        if hypothesis.get('attack_scenario'):
            parts.append(f"### 🧩 Hipótesis de Ataque")
            parts.append(f"{hypothesis['attack_scenario']}")
            if hypothesis.get('kill_chain_phase'):
                parts.append(f"**Fase Kill Chain:** {hypothesis['kill_chain_phase']}")
            if hypothesis.get('attacker_objective'):
                parts.append(f"**Objetivo:** {hypothesis['attacker_objective']}")
            parts.append("")

        # Predicciones
        if hypothesis.get('next_steps_prediction'):
            parts.append(f"### 🔮 Predicciones")
            for pred in hypothesis['next_steps_prediction'][:3]:
                parts.append(f"• {pred}")
            parts.append("")

        # Recomendaciones defensivas
        recommendations = hypothesis.get('defensive_recommendations') or final_report.get('immediate_actions', [])
        if recommendations:
            parts.append(f"### 🛡️ Acciones Defensivas")
            for rec in recommendations[:5]:
                parts.append(f"• {rec}")
            parts.append("")

        # OSINT Web
        if web_search.get('summary'):
            parts.append(f"### 🌐 Inteligencia OSINT")
            parts.append(f"{web_search['summary']}")
            parts.append("")

        # Fuentes de referencia
        if web_search.get('threat_reports'):
            parts.append(f"### 📚 Fuentes")
            for source in web_search['threat_reports'][:4]:
                name = source.get('name', 'Link')
                url = source.get('url', '#')
                parts.append(f"• [{name}]({url})")
            parts.append("")

        # Correlaciones
        if correlations.get('analysis') and 'No hay otros' not in correlations.get('analysis', ''):
            parts.append(f"### 🔗 Correlaciones")
            parts.append(f"{correlations['analysis'][:300]}")
            parts.append("")

        # APIs consultadas
        sources = base_analysis.get('sources_used', [])
        if sources:
            parts.append(f"*APIs consultadas: {', '.join(sources[:8])}*")

        # Tiempo y módulos
        modules = len(result.get('modules_executed', []))
        time_taken = result.get('processing_time', 0)
        parts.append(f"*Análisis completado en {time_taken:.1f}s | {modules} módulos ejecutados*")

        return '\n'.join(parts)