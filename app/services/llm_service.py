"""
Servicio de análisis con LLM (Large Language Models)
Soporte para: xAI (Grok), OpenAI, DeepSeek, Gemini y Kimi (Moonshot)
"""
import requests
import json
import logging
import re
from typing import Dict, Optional, Any
from flask import current_app
from app.utils.http_client import get_http_session, http_post

logger = logging.getLogger(__name__)


class LLMService:
    """Servicio para análisis contextual usando LLMs"""

    def __init__(self, provider: str = None):
        """
        Inicializa el servicio LLM
        Args:
            provider: 'xai', 'openai', 'deepseek', 'gemini', 'kimi' o None (detecta automático)
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

        # Prioridad (LLM_PRIORITY en config): xAI > OpenAI > DeepSeek > Gemini > Kimi
        for provider in current_app.config.get('LLM_PRIORITY', ['xai', 'openai', 'deepseek', 'gemini', 'kimi']):
            if api_keys.get(provider):
                return provider
        return None

    def _configure_provider(self):
        """Configura los endpoints y modelos según el proveedor (Actualizado 2026)"""
        api_keys = current_app.config.get('API_KEYS', {})
        llm_models = current_app.config.get('LLM_MODELS', {})

        if self.provider == 'xai':
            self.api_key = api_keys.get('xai')
            self.base_url = "https://api.x.ai/v1"
            self.model = llm_models.get('xai', {}).get('model', 'grok-3-mini')

        elif self.provider == 'deepseek':
            self.api_key = api_keys.get('deepseek')
            cfg = llm_models.get('deepseek', {})
            self.base_url = cfg.get('base_url', "https://api.deepseek.com/v1")
            self.model = cfg.get('model', 'deepseek-flash')

        elif self.provider == 'kimi':
            self.api_key = api_keys.get('kimi')
            cfg = llm_models.get('kimi', {})
            self.base_url = cfg.get('base_url', "https://api.moonshot.ai/v1")
            self.model = cfg.get('model', 'kimi-k3')

        elif self.provider == 'openai':
            self.api_key = api_keys.get('openai')
            self.base_url = "https://api.openai.com/v1"
            self.model = llm_models.get('openai', {}).get('model', 'gpt-4o-mini')

        elif self.provider == 'gemini':
            self.api_key = api_keys.get('gemini')
            self.base_url = "https://generativelanguage.googleapis.com/v1beta"
            self.model = llm_models.get('gemini', {}).get('model', 'gemini-2.5-flash')

    def generate(self, prompt: str) -> Dict:
        """Invoca el LLM configurado (xAI, OpenAI, DeepSeek, Gemini, Kimi) de forma uniforme."""
        if not self.provider or not self.api_key:
            return {'error': 'No LLM provider or API key configured'}

        try:
            if self.provider in ('xai', 'openai', 'deepseek', 'kimi'):
                return self._call_generic_openai_style(prompt)
            elif self.provider == 'gemini':
                return self._call_gemini(prompt)
            else:
                return {'error': f'Unsupported provider: {self.provider}'}
        except Exception as e:
            logger.error(f"LLM generate Error ({self.provider}): {e}")
            return {'error': f'LLM service error: {str(e)}'}

    def analyze_context(self, ioc_data: Dict) -> Dict:
        """Analiza contexto de IOC usando el LLM configurado"""
        if not self.provider or not self.api_key:
            return self._fallback_analysis(ioc_data)

        prompt = self._build_prompt(ioc_data)
        return self.generate(prompt)

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

    def _call_generic_openai_style(self, prompt: str) -> Any:
        """
        Cliente genérico para APIs compatibles con OpenAI (xAI, OpenAI, DeepSeek, Kimi)
        """
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }

        max_tokens = 4096
        temperature = 0.1
        try:
            if current_app:
                cfg = current_app.config.get('LLM_MODELS', {}).get(self.provider, {})
                max_tokens = cfg.get('max_tokens', 4096)
                # Kimi solo acepta temperature=1 (400 "invalid temperature" con otro valor)
                temperature = cfg.get('fixed_temperature', temperature)
        except Exception:
            pass

        data = {
            'model': self.model,
            'messages': [{'role': 'user', 'content': prompt}],
            'temperature': temperature,
            'max_tokens': max_tokens
        }

        # xAI a veces requiere stream=False explícito
        if self.provider == 'xai':
            data['stream'] = False

        try:
            response = http_post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=data,
                timeout=45
            )

            if response.status_code != 200:
                logger.error(f"API Error {self.provider} ({response.status_code}): {response.text}")
                return {'error': f'{self.provider} API error: {response.status_code}'}

            result = response.json()
            choices = result.get('choices', [])
            if not choices:
                return {'error': f'{self.provider} no devolvió opciones'}

            message = choices[0].get('message', {})
            if message.get('refusal'):
                logger.warning(f"{self.provider} rechazó el prompt: {message.get('refusal')}")
                return {'error': f"{self.provider} refusal: {message.get('refusal')}"}

            content = message.get('content')
            if content is None:
                return {'error': f'{self.provider} retornó contenido nulo'}

            return self._extract_json(content)

        except Exception as e:
            logger.error(f"Exception in _call_generic_openai_style ({self.provider}): {e}")
            return {'error': str(e)}

    def _call_gemini(self, prompt: str) -> Any:
        """Llamada a Gemini API pasando la clave por header x-goog-api-key"""
        url = f"{self.base_url}/models/{self.model}:generateContent"
        headers = {
            'Content-Type': 'application/json',
            'x-goog-api-key': self.api_key
        }

        max_tokens = 4096
        try:
            if current_app:
                max_tokens = current_app.config.get('LLM_MODELS', {}).get('gemini', {}).get('max_tokens', 4096)
        except Exception:
            pass

        data = {
            'contents': [{'parts': [{'text': prompt}]}],
            'generationConfig': {
                'temperature': 0.1,
                'maxOutputTokens': max_tokens
            }
        }

        try:
            response = http_post(url, headers=headers, json=data, timeout=45)
            if response.status_code != 200:
                logger.error(f"Gemini API error ({response.status_code}): {response.text}")
                return {'error': f'Gemini error: {response.status_code}'}

            result = response.json()
            candidates = result.get('candidates', [])
            if not candidates:
                feedback = result.get('promptFeedback', {})
                block_reason = feedback.get('blockReason')
                if block_reason:
                    return {'error': f'Gemini bloqueó el prompt: {block_reason}'}
                return {'error': 'Gemini no retornó contenido'}

            candidate = candidates[0]
            finish_reason = candidate.get('finishReason')
            if finish_reason in ('SAFETY', 'RECITATION', 'BLOCKLIST', 'PROHIBITED_CONTENT'):
                return {'error': f'Gemini finalizó por política: {finish_reason}'}

            parts = candidate.get('content', {}).get('parts', [])
            if not parts:
                return {'error': 'Gemini no retornó partes en el contenido'}

            content_text = "".join(p.get('text', '') for p in parts if isinstance(p, dict) and 'text' in p)
            if not content_text:
                return {'error': 'Gemini retornó partes sin texto'}

            return self._extract_json(content_text)
        except Exception as e:
            logger.error(f"Exception in _call_gemini: {e}")
            return {'error': str(e)}

    def _extract_json(self, text: str) -> Any:
        """
        Extrae JSON de manera robusta.
        Maneja fences Markdown (```json ... ```), objetos {...} y arrays [...].
        """
        if not text:
            return {'analysis': '', 'raw_text': True}

        cleaned = text.strip()

        # 1. Quitar markdown code blocks si existen
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
            cleaned = re.sub(r"\s*```$", "", cleaned)
            cleaned = cleaned.strip()

        # 2. Intentar carga directa
        try:
            return json.loads(cleaned)
        except Exception:
            pass

        # 3. Buscar patrón JSON {...}
        match_obj = re.search(r'\{.*\}', cleaned, re.DOTALL)
        if match_obj:
            try:
                return json.loads(match_obj.group(0))
            except Exception:
                pass

        # 4. Buscar patrón JSON [...]
        match_arr = re.search(r'\[.*\]', cleaned, re.DOTALL)
        if match_arr:
            try:
                return json.loads(match_arr.group(0))
            except Exception:
                pass

        # 5. Fallback: devolver texto envuelto
        return {'analysis': text, 'raw_text': True}

    def _fallback_analysis(self, ioc_data: Dict) -> Dict:
        """Análisis offline si fallan las APIs"""
        return {
            'summary': f"Análisis offline para {ioc_data.get('ioc')}",
            'threat_level': 'UNKNOWN',
            'recommendations': ['Verificar logs', 'Configurar API Keys'],
            'note': 'LLM no disponible'
        }