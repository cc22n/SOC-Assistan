"""
Servicio de análisis con LLM (Large Language Models)
Soporte para: Groq, OpenAI, Gemini, xAI (Grok) y Anthropic (Claude)
"""
import requests
import json
import logging
import re
from typing import Dict, Optional
from flask import current_app

logger = logging.getLogger(__name__)


class LLMService:
    """Servicio para análisis contextual usando LLMs"""

    def __init__(self, provider: str = None):
        """
        Inicializa el servicio LLM
        Args:
            provider: 'groq', 'openai', 'gemini', 'xai' o None (detecta automático)
        """
        self.provider = provider or self._detect_available_provider()
        self.api_key = None
        self.base_url = None
        self.model = None

        if self.provider:
            self._configure_provider()

    def _detect_available_provider(self) -> Optional[str]:
        """Detecta qué proveedor LLM está configurado y disponible"""
        api_keys = current_app.config.get('API_KEYS', {})

        # Prioridad sugerida: xAI > OpenAI > Groq > Gemini > Anthropic
        if api_keys.get('xai'):
            return 'xai'
        elif api_keys.get('openai'):
            return 'openai'
        elif api_keys.get('groq'):
            return 'groq'
        elif api_keys.get('gemini'):
            return 'gemini'
        elif api_keys.get('anthropic'):
            return 'anthropic'
        return None

    def _configure_provider(self):
        """Configura los endpoints y modelos según el proveedor (Actualizado 2026)"""
        api_keys = current_app.config.get('API_KEYS', {})
        llm_models = current_app.config.get('LLM_MODELS', {})

        if self.provider == 'xai':
            self.api_key = api_keys.get('xai')
            self.base_url = "https://api.x.ai/v1"
            self.model = llm_models.get('xai', {}).get('model', 'grok-3-mini')

        elif self.provider == 'groq':
            self.api_key = api_keys.get('groq')
            self.base_url = "https://api.groq.com/openai/v1"
            self.model = llm_models.get('groq', {}).get('model', 'llama-3.3-70b-versatile')

        elif self.provider == 'openai':
            self.api_key = api_keys.get('openai')
            self.base_url = "https://api.openai.com/v1"
            self.model = llm_models.get('openai', {}).get('model', 'gpt-4o-mini')

        elif self.provider == 'gemini':
            self.api_key = api_keys.get('gemini')
            self.base_url = "https://generativelanguage.googleapis.com/v1beta"
            self.model = llm_models.get('gemini', {}).get('model', 'gemini-2.5-flash')

        elif self.provider == 'anthropic':
            self.api_key = api_keys.get('anthropic')
            self.base_url = "https://api.anthropic.com/v1"
            self.model = llm_models.get('anthropic', {}).get('model', 'claude-sonnet-4-6')

    def analyze_context(self, ioc_data: Dict) -> Dict:
        """Analiza contexto de IOC usando el LLM configurado"""
        if not self.provider or not self.api_key:
            return self._fallback_analysis(ioc_data)

        prompt = self._build_prompt(ioc_data)

        try:
            if self.provider == 'xai':
                return self._call_generic_openai_style(prompt)  # xAI es compatible con OpenAI style
            elif self.provider == 'groq':
                return self._call_generic_openai_style(prompt)
            elif self.provider == 'openai':
                return self._call_generic_openai_style(prompt)
            elif self.provider == 'gemini':
                return self._call_gemini(prompt)
            elif self.provider == 'anthropic':
                return self._call_anthropic(prompt)
            else:
                return self._fallback_analysis(ioc_data)

        except Exception as e:
            logger.error(f"LLM Error ({self.provider}): {e}")
            return {'error': f'LLM service error: {str(e)}'}

    def _build_prompt(self, ioc_data: Dict) -> str:
        # Strip control characters from the IOC value before embedding it in the
        # prompt. API responses from third-party services could theoretically
        # contain instruction-override text in field values; serialising through
        # json.dumps already quotes strings, which limits the attack surface, but
        # we still strip null bytes and angle brackets from the IOC itself.
        raw_ioc = str(ioc_data.get('ioc', ''))
        safe_ioc = re.sub(r'[\x00-\x1f\x7f<>]', '', raw_ioc)[:512]
        safe_type = re.sub(r'[^\w]', '', str(ioc_data.get('type', '')))[:20]
        safe_score = int(ioc_data.get('confidence_score', 0)
                         if str(ioc_data.get('confidence_score', 0)).isdigit()
                         else 0)

        api_subset = {
            k: v for k, v in ioc_data.items()
            if k in ('virustotal', 'greynoise', 'threatfox')
        }

        return f"""Eres un analista SOC experto. Analiza:
        IOC: {safe_ioc} ({safe_type})
        Score: {safe_score}/100
        Datos: {json.dumps(api_subset, default=str)}

        Responde SOLO JSON:
        {{
            "summary": "...",
            "threat_level": "...",
            "recommendations": ["..."]
        }}"""

    def _call_generic_openai_style(self, prompt: str) -> Dict:
        """
        Cliente genérico para APIs compatibles con OpenAI (xAI, Groq, OpenAI)
        """
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }

        data = {
            'model': self.model,
            'messages': [{'role': 'user', 'content': prompt}],
            'temperature': 0.1,
            'max_tokens': 1024
        }

        # xAI a veces requiere stream=False explícito
        if self.provider == 'xai':
            data['stream'] = False

        try:
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=data,
                timeout=45
            )

            if response.status_code != 200:
                logger.error(f"API Error {self.provider}: {response.text}")
                return {'error': f'{self.provider} API error: {response.status_code}'}

            result = response.json()
            content = result['choices'][0]['message']['content']
            return self._extract_json(content)

        except Exception as e:
            return {'error': str(e)}

    def _call_gemini(self, prompt: str) -> Dict:
        """Llamada a Gemini API"""
        url = f"{self.base_url}/models/{self.model}:generateContent?key={self.api_key}"
        data = {
            'contents': [{'parts': [{'text': prompt}]}],
            'generationConfig': {'temperature': 0.1}
        }

        try:
            response = requests.post(url, json=data, timeout=30)
            if response.status_code != 200:
                return {'error': f'Gemini error: {response.status_code}'}

            result = response.json()
            # Manejo seguro de la estructura de respuesta de Gemini
            if 'candidates' in result and result['candidates']:
                content = result['candidates'][0]['content']['parts'][0]['text']
                return self._extract_json(content)
            else:
                return {'error': 'Gemini no retornó contenido'}
        except Exception as e:
            return {'error': str(e)}

    def _call_anthropic(self, prompt: str) -> Dict:
        """Llamada a Anthropic Messages API (Claude)"""
        headers = {
            'x-api-key': self.api_key,
            'anthropic-version': '2023-06-01',
            'Content-Type': 'application/json'
        }

        data = {
            'model': self.model,
            'max_tokens': 1024,
            'messages': [{'role': 'user', 'content': prompt}]
        }

        try:
            response = requests.post(
                f"{self.base_url}/messages",
                headers=headers,
                json=data,
                timeout=45
            )

            if response.status_code != 200:
                logger.error(f"Anthropic API Error: {response.text}")
                return {'error': f'Anthropic API error: {response.status_code}'}

            result = response.json()
            content = result['content'][0]['text']
            return self._extract_json(content)

        except Exception as e:
            return {'error': str(e)}

    def _extract_json(self, text: str) -> Dict:
        """
        Extrae JSON de manera robusta usando Regex
        Soluciona el problema de "No pude procesar la pregunta"
        """
        try:
            # 1. Intentar carga directa
            return json.loads(text)
        except:
            pass

        # 2. Buscar patrón JSON {...}
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except:
                pass

        # 3. Fallback: devolver texto envuelto
        return {'analysis': text, 'raw_text': True}

    def _fallback_analysis(self, ioc_data: Dict) -> Dict:
        """Análisis offline si fallan las APIs"""
        return {
            'summary': f"Análisis offline para {ioc_data.get('ioc')}",
            'threat_level': 'UNKNOWN',
            'recommendations': ['Verificar logs', 'Configurar API Keys'],
            'note': 'LLM no disponible'
        }