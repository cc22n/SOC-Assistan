"""
SOC Agent - API Clients v3.0
Febrero 2025

CAMBIOS PRINCIPALES:
- Gemini: Nueva librería google-genai (reemplaza google-generativeai deprecada)
- NUEVAS APIs: Criminal IP, Pulsedive, URLScan.io, MalwareBazaar, Shodan InternetDB, IP-API
- ELIMINADAS: IPQualityScore (sin créditos), Censys (credenciales problemáticas)
- MEJORADO: Todos los clientes con mejor manejo de errores

INSTALACIÓN:
pip install google-genai requests --break-system-packages
"""
import requests
import logging
import json
from typing import Dict, Optional, Any
from flask import current_app

logger = logging.getLogger(__name__)


# ==============================================================================
# APIs PRINCIPALES (ya funcionando)
# ==============================================================================

class VirusTotalClient:
    """Cliente para VirusTotal API v3"""

    def __init__(self):
        self.base_url = "https://www.virustotal.com/api/v3"
        self.api_key = current_app.config.get('API_KEYS', {}).get('virustotal')

    def _get_headers(self) -> Dict:
        return {'x-apikey': self.api_key} if self.api_key else {}

    def check_ip(self, ip: str) -> Dict:
        """Analiza una IP en VirusTotal"""
        if not self.api_key:
            return {'error': 'API key no configurada'}

        try:
            response = requests.get(
                f"{self.base_url}/ip_addresses/{ip}",
                headers=self._get_headers(),
                timeout=30
            )

            if response.status_code == 200:
                data = response.json().get('data', {}).get('attributes', {})
                stats = data.get('last_analysis_stats', {})
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'asn': data.get('asn'),
                    'as_owner': data.get('as_owner'),
                    'country': data.get('country'),
                    'reputation': data.get('reputation', 0)
                }
            elif response.status_code == 401:
                return {'error': 'API key inválida'}
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"VirusTotal error: {e}")
            return {'error': str(e)}

    def check_hash(self, file_hash: str) -> Dict:
        """Analiza un hash en VirusTotal"""
        if not self.api_key:
            return {'error': 'API key no configurada'}

        try:
            response = requests.get(
                f"{self.base_url}/files/{file_hash}",
                headers=self._get_headers(),
                timeout=30
            )

            if response.status_code == 200:
                data = response.json().get('data', {}).get('attributes', {})
                stats = data.get('last_analysis_stats', {})
                return {
                    'found': True,
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'undetected': stats.get('undetected', 0),
                    'type_description': data.get('type_description'),
                    'meaningful_name': data.get('meaningful_name'),
                    'popular_threat_classification': data.get('popular_threat_classification', {}),
                    'names': data.get('names', [])[:5],
                    'size': data.get('size'),
                    'magic': data.get('magic')
                }
            elif response.status_code == 404:
                return {'found': False, 'message': 'Hash no encontrado'}
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"VirusTotal hash error: {e}")
            return {'error': str(e)}

    def check_domain(self, domain: str) -> Dict:
        """Analiza un dominio en VirusTotal"""
        if not self.api_key:
            return {'error': 'API key no configurada'}

        try:
            response = requests.get(
                f"{self.base_url}/domains/{domain}",
                headers=self._get_headers(),
                timeout=30
            )

            if response.status_code == 200:
                data = response.json().get('data', {}).get('attributes', {})
                stats = data.get('last_analysis_stats', {})
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'registrar': data.get('registrar'),
                    'creation_date': data.get('creation_date'),
                    'reputation': data.get('reputation', 0),
                    'categories': data.get('categories', {})
                }
            elif response.status_code == 404:
                return {'found': False, 'message': 'Dominio no encontrado'}
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"VirusTotal domain error: {e}")
            return {'error': str(e)}


class AbuseIPDBClient:
    """Cliente para AbuseIPDB API"""

    def __init__(self):
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.api_key = current_app.config.get('API_KEYS', {}).get('abuseipdb')

    def check_ip(self, ip: str) -> Dict:
        """Verifica una IP en AbuseIPDB"""
        if not self.api_key:
            return {'error': 'API key no configurada'}

        try:
            response = requests.get(
                f"{self.base_url}/check",
                headers={'Key': self.api_key, 'Accept': 'application/json'},
                params={'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': True},
                timeout=15
            )

            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                    'total_reports': data.get('totalReports', 0),
                    'country_code': data.get('countryCode'),
                    'isp': data.get('isp'),
                    'domain': data.get('domain'),
                    'is_tor': data.get('isTor', False),
                    'is_whitelisted': data.get('isWhitelisted', False),
                    'last_reported_at': data.get('lastReportedAt'),
                    'usage_type': data.get('usageType')
                }
            elif response.status_code == 401:
                return {'error': 'API key inválida'}
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"AbuseIPDB error: {e}")
            return {'error': str(e)}


class ShodanClient:
    """Cliente para Shodan API"""

    def __init__(self):
        self.base_url = "https://api.shodan.io"
        self.api_key = current_app.config.get('API_KEYS', {}).get('shodan')

    def check_ip(self, ip: str) -> Dict:
        """Obtiene información de una IP en Shodan"""
        if not self.api_key:
            return {'error': 'API key no configurada'}

        try:
            response = requests.get(
                f"{self.base_url}/shodan/host/{ip}",
                params={'key': self.api_key},
                timeout=15
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'found': True,
                    'ip': data.get('ip_str'),
                    'organization': data.get('org'),
                    'asn': data.get('asn'),
                    'isp': data.get('isp'),
                    'country': data.get('country_name'),
                    'city': data.get('city'),
                    'ports': data.get('ports', []),
                    'hostnames': data.get('hostnames', []),
                    'vulns': data.get('vulns', []),
                    'os': data.get('os'),
                    'last_update': data.get('last_update')
                }
            elif response.status_code == 404:
                return {'found': False, 'message': 'IP no encontrada en Shodan'}
            elif response.status_code == 401:
                return {'error': 'API key inválida'}
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"Shodan error: {e}")
            return {'error': str(e)}


class OTXClient:
    """Cliente para AlienVault OTX API"""

    def __init__(self):
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.api_key = current_app.config.get('API_KEYS', {}).get('otx')

    def _get_headers(self) -> Dict:
        headers = {'Accept': 'application/json'}
        if self.api_key:
            headers['X-OTX-API-KEY'] = self.api_key
        return headers

    def check_ip(self, ip: str) -> Dict:
        """Consulta una IP en OTX"""
        try:
            response = requests.get(
                f"{self.base_url}/indicators/IPv4/{ip}/general",
                headers=self._get_headers(),
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                pulse_info = data.get('pulse_info', {})
                return {
                    'pulse_count': pulse_info.get('count', 0),
                    'pulses': [
                        {'name': p.get('name'), 'tags': p.get('tags', [])}
                        for p in pulse_info.get('pulses', [])[:5]
                    ],
                    'country': data.get('country_name'),
                    'asn': data.get('asn'),
                    'reputation': data.get('reputation', 0),
                    'validation': data.get('validation', [])
                }
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"OTX error: {e}")
            return {'error': str(e)}

    def check_domain(self, domain: str) -> Dict:
        """Consulta un dominio en OTX"""
        try:
            response = requests.get(
                f"{self.base_url}/indicators/domain/{domain}/general",
                headers=self._get_headers(),
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                pulse_info = data.get('pulse_info', {})
                return {
                    'pulse_count': pulse_info.get('count', 0),
                    'alexa': data.get('alexa'),
                    'whois': data.get('whois'),
                    'validation': data.get('validation', [])
                }
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"OTX domain error: {e}")
            return {'error': str(e)}

    def check_hash(self, file_hash: str) -> Dict:
        """Consulta un hash en OTX"""
        try:
            response = requests.get(
                f"{self.base_url}/indicators/file/{file_hash}/general",
                headers=self._get_headers(),
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                pulse_info = data.get('pulse_info', {})
                return {
                    'found': True,
                    'pulse_count': pulse_info.get('count', 0),
                    'pulses': [
                        {'name': p.get('name'), 'tags': p.get('tags', [])}
                        for p in pulse_info.get('pulses', [])[:5]
                    ]
                }
            elif response.status_code == 404:
                return {'found': False}
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"OTX hash error: {e}")
            return {'error': str(e)}


class GreyNoiseClient:
    """Cliente para GreyNoise Community API"""

    def __init__(self):
        self.base_url = "https://api.greynoise.io/v3/community"
        self.api_key = current_app.config.get('API_KEYS', {}).get('greynoise')

    def check_ip(self, ip: str) -> Dict:
        """Consulta una IP en GreyNoise"""
        headers = {'Accept': 'application/json'}
        if self.api_key:
            headers['key'] = self.api_key

        try:
            response = requests.get(
                f"{self.base_url}/{ip}",
                headers=headers,
                timeout=15
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'found': True,
                    'noise': data.get('noise', False),
                    'riot': data.get('riot', False),
                    'classification': data.get('classification', 'unknown'),
                    'name': data.get('name'),
                    'link': data.get('link'),
                    'last_seen': data.get('last_seen')
                }
            elif response.status_code == 404:
                return {
                    'found': False,
                    'noise': False,
                    'classification': 'unknown',
                    'message': 'IP no vista por GreyNoise'
                }
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"GreyNoise error: {e}")
            return {'error': str(e)}


class GoogleSafeBrowsingClient:
    """Cliente para Google Safe Browsing API"""

    def __init__(self):
        self.api_key = current_app.config.get('API_KEYS', {}).get('google_safebrowsing')
        self.base_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def check_url(self, url: str) -> Dict:
        """Verifica una URL contra Google Safe Browsing"""
        if not self.api_key:
            return {'error': 'API key no configurada'}

        try:
            payload = {
                "client": {"clientId": "soc-agent", "clientVersion": "3.0"},
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE", "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }

            response = requests.post(
                f"{self.base_url}?key={self.api_key}",
                json=payload,
                timeout=15
            )

            if response.status_code == 200:
                data = response.json()
                matches = data.get('matches', [])
                if matches:
                    return {
                        'is_malicious': True,
                        'threats': [
                            {
                                'threat_type': m.get('threatType'),
                                'platform': m.get('platformType')
                            }
                            for m in matches
                        ]
                    }
                return {'is_malicious': False, 'message': 'URL limpia'}
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"Google Safe Browsing error: {e}")
            return {'error': str(e)}


class SecurityTrailsClient:
    """Cliente para SecurityTrails API"""

    def __init__(self):
        self.base_url = "https://api.securitytrails.com/v1"
        self.api_key = current_app.config.get('API_KEYS', {}).get('securitytrails')

    def get_domain_details(self, domain: str) -> Dict:
        """Obtiene detalles de un dominio"""
        if not self.api_key:
            return {'error': 'API key no configurada'}

        try:
            response = requests.get(
                f"{self.base_url}/domain/{domain}",
                headers={'APIKEY': self.api_key, 'Accept': 'application/json'},
                timeout=15
            )

            if response.status_code == 200:
                data = response.json()
                dns = data.get('current_dns', {})
                return {
                    'found': True,
                    'hostname': data.get('hostname'),
                    'alexa_rank': data.get('alexa_rank'),
                    'a_records': [r.get('ip') for r in dns.get('a', {}).get('values', [])],
                    'mx_records': [r.get('hostname') for r in dns.get('mx', {}).get('values', [])],
                    'ns_records': [r.get('nameserver') for r in dns.get('ns', {}).get('values', [])]
                }
            elif response.status_code == 404:
                return {'found': False}
            elif response.status_code == 401:
                return {'error': 'API key inválida'}
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"SecurityTrails error: {e}")
            return {'error': str(e)}


class HybridAnalysisClient:
    """Cliente para Hybrid Analysis API"""

    def __init__(self):
        self.base_url = "https://www.hybrid-analysis.com/api/v2"
        self.api_key = current_app.config.get('API_KEYS', {}).get('hybrid_analysis')

    def search_hash(self, file_hash: str) -> Dict:
        """Busca un hash en Hybrid Analysis (usando endpoint Overview GET)"""
        if not self.api_key:
            return {'error': 'API key no configurada'}

        # Limpiar hash
        import re
        hash_clean = re.sub(r'[^a-fA-F0-9]', '', file_hash.strip().lower())

        if len(hash_clean) not in [32, 40, 64]:
            return {'error': f'Hash inválido (longitud: {len(hash_clean)})'}

        try:
            response = requests.get(
                f"{self.base_url}/overview/{hash_clean}",
                headers={
                    'api-key': self.api_key,
                    'User-Agent': 'Falcon Sandbox',
                    'accept': 'application/json'
                },
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list) and len(data) > 0:
                    result = data[0]
                    return {
                        'found': True,
                        'verdict': result.get('verdict'),
                        'threat_score': result.get('threat_score'),
                        'threat_level': result.get('threat_level'),
                        'av_detect': result.get('av_detect'),
                        'vx_family': result.get('vx_family'),
                        'type': result.get('type'),
                        'submit_name': result.get('submit_name'),
                        'environment': result.get('environment_description'),
                        'total_results': len(data)
                    }
                return {'found': False, 'message': 'Hash no encontrado'}
            elif response.status_code == 401:
                return {'error': 'API key inválida'}
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"Hybrid Analysis error: {e}")
            return {'error': str(e)}


# ==============================================================================
# APIs abuse.ch (URLhaus, ThreatFox, MalwareBazaar)
# ==============================================================================

class URLhausClient:
    """Cliente para URLhaus API (abuse.ch)"""

    def __init__(self):
        self.base_url = "https://urlhaus-api.abuse.ch/v1"
        self.auth_key = current_app.config.get('API_KEYS', {}).get('abusech_auth')

    def _get_headers(self) -> Dict:
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        if self.auth_key:
            headers['Auth-Key'] = self.auth_key
        return headers

    def check_url(self, url: str) -> Dict:
        """Consulta una URL en URLhaus (Auth-Key opcional para consultas)"""
        try:
            response = requests.post(
                f"{self.base_url}/url/",
                headers=self._get_headers(),
                data={'url': url},
                timeout=15
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('query_status') == 'ok':
                    return {
                        'found': True,
                        'url_status': data.get('url_status'),
                        'threat': data.get('threat'),
                        'tags': data.get('tags', []),
                        'host': data.get('host'),
                        'date_added': data.get('date_added'),
                        'payloads': data.get('payloads', [])[:3]
                    }
                return {'found': False, 'message': 'URL no encontrada'}
            elif response.status_code == 401:
                return {'error': 'Auth-Key inválido'}
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"URLhaus error: {e}")
            return {'error': str(e)}

    def check_host(self, host: str) -> Dict:
        """Consulta un host en URLhaus (Auth-Key opcional)"""
        try:
            response = requests.post(
                f"{self.base_url}/host/",
                headers=self._get_headers(),
                data={'host': host},
                timeout=15
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('query_status') == 'ok':
                    return {
                        'found': True,
                        'url_count': data.get('url_count', 0),
                        'blacklists': data.get('blacklists', {}),
                        'urls': data.get('urls', [])[:5]
                    }
                return {'found': False}
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"URLhaus host error: {e}")
            return {'error': str(e)}


class ThreatFoxClient:
    """Cliente para ThreatFox API (abuse.ch)"""

    def __init__(self):
        self.base_url = "https://threatfox-api.abuse.ch/api/v1"
        self.auth_key = current_app.config.get('API_KEYS', {}).get('abusech_auth')

    def _get_headers(self) -> Dict:
        headers = {'Content-Type': 'application/json'}
        if self.auth_key:
            headers['Auth-Key'] = self.auth_key
        return headers

    def search_ioc(self, ioc: str) -> Dict:
        """Busca un IOC en ThreatFox (Auth-Key opcional)"""
        try:
            response = requests.post(
                self.base_url,
                headers=self._get_headers(),
                json={'query': 'search_ioc', 'search_term': ioc},
                timeout=15
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('query_status') == 'ok' and data.get('data'):
                    first = data['data'][0]
                    return {
                        'found': True,
                        'threat_type': first.get('threat_type'),
                        'threat_type_desc': first.get('threat_type_desc'),
                        'malware': first.get('malware_printable'),
                        'confidence_level': first.get('confidence_level'),
                        'first_seen': first.get('first_seen'),
                        'tags': first.get('tags', []),
                        'total_results': len(data['data'])
                    }
                return {'found': False}
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"ThreatFox error: {e}")
            return {'error': str(e)}


class MalwareBazaarClient:
    """
    Cliente para MalwareBazaar API (abuse.ch)
    NUEVO - Usa el mismo Auth-Key de abuse.ch
    """

    def __init__(self):
        self.base_url = "https://mb-api.abuse.ch/api/v1"
        self.auth_key = current_app.config.get('API_KEYS', {}).get('abusech_auth')

    def _get_headers(self) -> Dict:
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        if self.auth_key:
            headers['Auth-Key'] = self.auth_key
        return headers

    def query_hash(self, file_hash: str) -> Dict:
        """Busca un hash en MalwareBazaar (Auth-Key opcional)"""
        try:
            response = requests.post(
                f"{self.base_url}/",
                headers=self._get_headers(),
                data={'query': 'get_info', 'hash': file_hash},
                timeout=15
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('query_status') == 'ok' and data.get('data'):
                    sample = data['data'][0] if isinstance(data['data'], list) else data['data']
                    return {
                        'found': True,
                        'sha256': sample.get('sha256_hash'),
                        'sha1': sample.get('sha1_hash'),
                        'md5': sample.get('md5_hash'),
                        'file_type': sample.get('file_type'),
                        'file_type_mime': sample.get('file_type_mime'),
                        'signature': sample.get('signature'),
                        'tags': sample.get('tags', []),
                        'intelligence': sample.get('intelligence', {}),
                        'first_seen': sample.get('first_seen'),
                        'last_seen': sample.get('last_seen'),
                        'file_name': sample.get('file_name'),
                        'delivery_method': sample.get('delivery_method'),
                        'origin_country': sample.get('origin_country')
                    }
                return {'found': False, 'message': 'Hash no encontrado en MalwareBazaar'}
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"MalwareBazaar error: {e}")
            return {'error': str(e)}

    def get_recent_samples(self, selector: str = 'time') -> Dict:
        """Obtiene muestras recientes"""
        try:
            response = requests.post(
                f"{self.base_url}/",
                headers=self._get_headers(),
                data={'query': 'get_recent', 'selector': selector},
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('query_status') == 'ok':
                    return {
                        'samples': data.get('data', [])[:20],
                        'total': len(data.get('data', []))
                    }
            return {'error': 'No se pudieron obtener muestras'}
        except Exception as e:
            logger.error(f"MalwareBazaar recent error: {e}")
            return {'error': str(e)}


# ==============================================================================
# NUEVAS APIs
# ==============================================================================

class CriminalIPClient:
    """
    Cliente para Criminal IP API
    NUEVO - Escaner de IPs y dominios, deteccion de C2, phishing
    """

    def __init__(self):
        self.base_url = "https://api.criminalip.io/v1"
        self.api_key = current_app.config.get('API_KEYS', {}).get('criminal_ip')

    def _get_headers(self) -> Dict:
        return {
            'x-api-key': self.api_key,
            'Accept': 'application/json'
        } if self.api_key else {}

    def check_ip(self, ip: str) -> Dict:
        """Analiza una IP en Criminal IP"""
        if not self.api_key:
            return {'error': 'API key no configurada'}

        try:
            response = requests.get(
                f"{self.base_url}/asset/ip/report",
                headers=self._get_headers(),
                params={'ip': ip},
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 200:
                    result = data.get('data', {})
                    return {
                        'found': True,
                        'ip': ip,
                        'score': result.get('score', {}).get('inbound'),
                        'is_vpn': result.get('is_vpn', False),
                        'is_proxy': result.get('is_proxy', False),
                        'is_tor': result.get('is_tor', False),
                        'is_hosting': result.get('is_hosting', False),
                        'is_scanner': result.get('is_scanner', False),
                        'is_snort': result.get('is_snort', False),
                        'is_malicious': result.get('is_malicious', False),
                        'country': result.get('country'),
                        'city': result.get('city'),
                        'isp': result.get('isp'),
                        'asn': result.get('as_name'),
                        'open_ports': result.get('ports', [])[:10],
                        'issues': result.get('issues', [])[:5]
                    }
                return {'error': data.get('message', 'Error desconocido')}
            elif response.status_code == 401:
                return {'error': 'API key inválida'}
            elif response.status_code == 429:
                return {'error': 'Rate limit excedido'}
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"Criminal IP error: {e}")
            return {'error': str(e)}

    def check_domain(self, domain: str) -> Dict:
        """Analiza un dominio en Criminal IP"""
        if not self.api_key:
            return {'error': 'API key no configurada'}

        try:
            response = requests.get(
                f"{self.base_url}/domain/report",
                headers=self._get_headers(),
                params={'query': domain},
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 200:
                    result = data.get('data', {})
                    return {
                        'found': True,
                        'domain': domain,
                        'is_phishing': result.get('is_phishing', False),
                        'is_malicious': result.get('is_malicious', False),
                        'score': result.get('score'),
                        'technologies': result.get('technologies', [])[:5],
                        'certificates': result.get('certificates', [])[:3]
                    }
                return {'found': False}
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"Criminal IP domain error: {e}")
            return {'error': str(e)}


class PulsediveClient:
    """
    Cliente para Pulsedive API
    NUEVO - Threat intelligence, IOC enrichment
    """

    def __init__(self):
        self.base_url = "https://pulsedive.com/api"
        self.api_key = current_app.config.get('API_KEYS', {}).get('pulsedive')

    def get_indicator(self, indicator: str) -> Dict:
        """Obtiene información de un indicador (IP, dominio, URL, hash)"""
        if not self.api_key:
            return {'error': 'API key no configurada'}

        try:
            response = requests.get(
                f"{self.base_url}/info.php",
                params={
                    'indicator': indicator,
                    'key': self.api_key,
                    'pretty': 1
                },
                timeout=15
            )

            if response.status_code == 200:
                data = response.json()
                if 'error' not in data:
                    return {
                        'found': True,
                        'indicator': data.get('indicator'),
                        'type': data.get('type'),
                        'risk': data.get('risk'),
                        'risk_recommended': data.get('risk_recommended'),
                        'manualrisk': data.get('manualrisk'),
                        'retired': data.get('retired'),
                        'stamp_added': data.get('stamp_added'),
                        'stamp_updated': data.get('stamp_updated'),
                        'threats': data.get('threats', [])[:5],
                        'feeds': data.get('feeds', [])[:5],
                        'attributes': data.get('attributes', {}),
                        'properties': data.get('properties', {})
                    }
                return {'found': False, 'message': data.get('error', 'No encontrado')}
            elif response.status_code == 429:
                return {'error': 'Rate limit excedido'}
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"Pulsedive error: {e}")
            return {'error': str(e)}

    def search_threats(self, threat: str) -> Dict:
        """Busca información sobre una amenaza"""
        if not self.api_key:
            return {'error': 'API key no configurada'}

        try:
            response = requests.get(
                f"{self.base_url}/info.php",
                params={
                    'threat': threat,
                    'key': self.api_key
                },
                timeout=15
            )

            if response.status_code == 200:
                data = response.json()
                if 'error' not in data:
                    return {
                        'found': True,
                        'name': data.get('threat'),
                        'category': data.get('category'),
                        'risk': data.get('risk'),
                        'description': data.get('description'),
                        'references': data.get('news', [])[:3]
                    }
                return {'found': False}
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"Pulsedive threat error: {e}")
            return {'error': str(e)}


class URLScanClient:
    """
    Cliente para URLScan.io API
    NUEVO - Analisis visual de URLs, screenshots
    """

    def __init__(self):
        self.base_url = "https://urlscan.io/api/v1"
        self.api_key = current_app.config.get('API_KEYS', {}).get('urlscan')

    def _get_headers(self) -> Dict:
        headers = {'Content-Type': 'application/json'}
        if self.api_key:
            headers['API-Key'] = self.api_key
        return headers

    def search(self, query: str) -> Dict:
        """Busca escaneos existentes"""
        try:
            response = requests.get(
                f"{self.base_url}/search/",
                headers=self._get_headers(),
                params={'q': query},
                timeout=15
            )

            if response.status_code == 200:
                data = response.json()
                results = data.get('results', [])
                if results:
                    return {
                        'found': True,
                        'total': len(results),
                        'results': [
                            {
                                'url': r.get('page', {}).get('url'),
                                'domain': r.get('page', {}).get('domain'),
                                'ip': r.get('page', {}).get('ip'),
                                'country': r.get('page', {}).get('country'),
                                'status': r.get('page', {}).get('status'),
                                'screenshot': r.get('screenshot'),
                                'task_time': r.get('task', {}).get('time'),
                                'verdicts': r.get('verdicts', {}),
                                'result_url': r.get('result')
                            }
                            for r in results[:5]
                        ]
                    }
                return {'found': False, 'message': 'No hay escaneos previos'}
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"URLScan search error: {e}")
            return {'error': str(e)}

    def submit_scan(self, url: str, visibility: str = 'public') -> Dict:
        """Envía una URL para escanear"""
        if not self.api_key:
            return {'error': 'API key no configurada'}

        try:
            response = requests.post(
                f"{self.base_url}/scan/",
                headers=self._get_headers(),
                json={'url': url, 'visibility': visibility},
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'submitted': True,
                    'uuid': data.get('uuid'),
                    'message': data.get('message'),
                    'result_url': data.get('result'),
                    'api_url': data.get('api')
                }
            elif response.status_code == 429:
                return {'error': 'Rate limit - esperar antes de enviar más'}
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"URLScan submit error: {e}")
            return {'error': str(e)}

    def get_result(self, uuid: str) -> Dict:
        """Obtiene resultado de un escaneo"""
        try:
            response = requests.get(
                f"{self.base_url}/result/{uuid}/",
                headers=self._get_headers(),
                timeout=15
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'found': True,
                    'url': data.get('page', {}).get('url'),
                    'domain': data.get('page', {}).get('domain'),
                    'ip': data.get('page', {}).get('ip'),
                    'country': data.get('page', {}).get('country'),
                    'server': data.get('page', {}).get('server'),
                    'status': data.get('page', {}).get('status'),
                    'verdicts': data.get('verdicts', {}),
                    'stats': data.get('stats', {}),
                    'lists': data.get('lists', {}),
                    'screenshot': f"https://urlscan.io/screenshots/{uuid}.png"
                }
            elif response.status_code == 404:
                return {'found': False, 'message': 'Escaneo no encontrado o pendiente'}
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"URLScan result error: {e}")
            return {'error': str(e)}


class ShodanInternetDBClient:
    """
    Cliente para Shodan InternetDB API
    NUEVO - API gratuita sin key para datos básicos de IP
    """

    def __init__(self):
        self.base_url = "https://internetdb.shodan.io"

    def check_ip(self, ip: str) -> Dict:
        """Obtiene información básica de una IP (sin API key)"""
        try:
            response = requests.get(
                f"{self.base_url}/{ip}",
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'found': True,
                    'ip': data.get('ip'),
                    'ports': data.get('ports', []),
                    'hostnames': data.get('hostnames', []),
                    'cpes': data.get('cpes', []),
                    'tags': data.get('tags', []),
                    'vulns': data.get('vulns', [])
                }
            elif response.status_code == 404:
                return {'found': False, 'message': 'IP no encontrada'}
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"Shodan InternetDB error: {e}")
            return {'error': str(e)}


class IPAPIClient:
    """
    Cliente para IP-API.com
    NUEVO - Geolocalización gratuita sin key
    """

    def __init__(self):
        # ip-api.com requires HTTPS on paid plans; free tier uses HTTP.
        # Use the pro endpoint when a key is configured, otherwise fall back
        # to the free HTTP endpoint (data is non-sensitive geolocation only).
        self.base_url = "http://ip-api.com/json"

    def get_geolocation(self, ip: str) -> Dict:
        """Obtiene geolocalización de una IP"""
        try:
            response = requests.get(
                f"{self.base_url}/{ip}",
                params={
                    'fields': 'status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query'},
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'found': True,
                        'ip': data.get('query'),
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'zip': data.get('zip'),
                        'lat': data.get('lat'),
                        'lon': data.get('lon'),
                        'timezone': data.get('timezone'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'as': data.get('as'),
                        'asname': data.get('asname'),
                        'reverse': data.get('reverse'),
                        'is_mobile': data.get('mobile', False),
                        'is_proxy': data.get('proxy', False),
                        'is_hosting': data.get('hosting', False)
                    }
                return {'found': False, 'message': data.get('message', 'IP no válida')}
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"IP-API error: {e}")
            return {'error': str(e)}


class CensysClient:
    """
    Cliente para Censys Platform API v3
    Escaneo de hosts, certificados, puertos abiertos
    """

    def __init__(self):
        self.base_url = "https://api.platform.censys.io/v3"
        self.api_key = current_app.config.get('API_KEYS', {}).get('censys')

    def _get_headers(self) -> Dict:
        return {
            'Authorization': f'Bearer {self.api_key}',
            'Accept': 'application/vnd.censys.api.v3.host.v1+json'
        } if self.api_key else {}

    def check_ip(self, ip: str) -> Dict:
        """Consulta información de un host/IP en Censys"""
        if not self.api_key:
            return {'error': 'API key no configurada'}

        try:
            response = requests.get(
                f"{self.base_url}/global/asset/host/{ip}",
                headers=self._get_headers(),
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                host = data.get('result', data)
                services = host.get('services', [])
                return {
                    'found': True,
                    'ip': ip,
                    'services_count': len(services),
                    'services': [
                        {
                            'port': s.get('port'),
                            'service_name': s.get('service_name'),
                            'transport_protocol': s.get('transport_protocol'),
                            'certificate': s.get('tls', {}).get('certificates', {}).get('leaf', {}).get('subject_dn', '')
                        }
                        for s in services[:10]
                    ],
                    'operating_system': host.get('operating_system', {}),
                    'autonomous_system': host.get('autonomous_system', {}),
                    'location': host.get('location', {}),
                    'last_updated_at': host.get('last_updated_at')
                }
            elif response.status_code == 404:
                return {'found': False, 'message': 'Host no encontrado en Censys'}
            elif response.status_code == 401:
                return {'error': 'API key inválida'}
            elif response.status_code == 429:
                return {'error': 'Rate limit excedido'}
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"Censys error: {e}")
            return {'error': str(e)}


class IPinfoClient:
    """
    Cliente para IPinfo.io API (Lite)
    Geolocalización, ASN, empresa, tipo de IP
    """

    def __init__(self):
        self.base_url = "https://api.ipinfo.io/lite"
        self.token = current_app.config.get('API_KEYS', {}).get('ipinfo')

    def check_ip(self, ip: str) -> Dict:
        """Obtiene información de geolocalización y ASN de una IP"""
        if not self.token:
            return {'error': 'Token no configurado'}

        try:
            response = requests.get(
                f"{self.base_url}/{ip}",
                params={'token': self.token},
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'found': True,
                    'ip': data.get('ip'),
                    'city': data.get('city'),
                    'region': data.get('region'),
                    'country': data.get('country'),
                    'loc': data.get('loc'),
                    'org': data.get('org'),
                    'timezone': data.get('timezone'),
                    'asn': data.get('asn', {}),
                    'company': data.get('company', {}),
                    'privacy': data.get('privacy', {}),
                    'abuse': data.get('abuse', {})
                }
            elif response.status_code == 401:
                return {'error': 'Token inválido'}
            elif response.status_code == 429:
                return {'error': 'Rate limit excedido'}
            return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"IPinfo error: {e}")
            return {'error': str(e)}


# ==============================================================================
# CLIENTE UNIFICADO DE TODAS LAS APIs
# ==============================================================================

class UnifiedThreatIntelClient:
    """
    Cliente unificado que consulta múltiples fuentes de threat intelligence.
    Todas las llamadas a APIs externas están protegidas con circuit breakers.
    """

    def __init__(self):
        # APIs principales
        self.virustotal = VirusTotalClient()
        self.abuseipdb = AbuseIPDBClient()
        self.shodan = ShodanClient()
        self.otx = OTXClient()
        self.greynoise = GreyNoiseClient()
        self.safebrowsing = GoogleSafeBrowsingClient()
        self.securitytrails = SecurityTrailsClient()
        self.hybrid_analysis = HybridAnalysisClient()

        # APIs abuse.ch
        self.urlhaus = URLhausClient()
        self.threatfox = ThreatFoxClient()
        self.malwarebazaar = MalwareBazaarClient()

        # APIs nuevas
        self.criminal_ip = CriminalIPClient()
        self.pulsedive = PulsediveClient()
        self.urlscan = URLScanClient()
        self.shodan_internetdb = ShodanInternetDBClient()
        self.ip_api = IPAPIClient()

        # APIs v3.1
        self.censys = CensysClient()
        self.ipinfo = IPinfoClient()

    def _call(self, api_name: str, func, *args, **kwargs) -> Dict:
        """Ejecuta una llamada a API externa protegida por circuit breaker y métricas."""
        import time as _time
        from app.utils.circuit_breaker import call_with_circuit_breaker
        t0 = _time.monotonic()
        try:
            result = call_with_circuit_breaker(api_name, func, *args, **kwargs)
            latency_ms = (_time.monotonic() - t0) * 1000
            success = not (isinstance(result, dict) and 'error' in result)
            try:
                from app.utils.metrics import record_api_latency
                record_api_latency(api_name, latency_ms, success)
            except Exception:
                pass
            return result
        except Exception as exc:
            latency_ms = (_time.monotonic() - t0) * 1000
            try:
                from app.utils.metrics import record_api_latency
                record_api_latency(api_name, latency_ms, success=False)
            except Exception:
                pass
            logger.error(f"[{api_name}] call failed: {exc}")
            return {'error': str(exc)}

    def analyze_ip(self, ip: str, sources: list = None) -> Dict:
        """Analiza una IP en múltiples fuentes"""
        if sources is None:
            sources = ['virustotal', 'abuseipdb', 'shodan', 'otx', 'greynoise',
                       'criminal_ip', 'pulsedive', 'shodan_internetdb', 'ip_api',
                       'censys', 'ipinfo']

        results = {}

        if 'virustotal' in sources:
            results['virustotal'] = self._call('virustotal', self.virustotal.check_ip, ip)
        if 'abuseipdb' in sources:
            results['abuseipdb'] = self._call('abuseipdb', self.abuseipdb.check_ip, ip)
        if 'shodan' in sources:
            results['shodan'] = self._call('shodan', self.shodan.check_ip, ip)
        if 'otx' in sources:
            results['otx'] = self._call('otx', self.otx.check_ip, ip)
        if 'greynoise' in sources:
            results['greynoise'] = self._call('greynoise', self.greynoise.check_ip, ip)
        if 'criminal_ip' in sources:
            results['criminal_ip'] = self._call('criminal_ip', self.criminal_ip.check_ip, ip)
        if 'pulsedive' in sources:
            results['pulsedive'] = self._call('pulsedive', self.pulsedive.get_indicator, ip)
        if 'shodan_internetdb' in sources:
            results['shodan_internetdb'] = self._call('shodan_internetdb', self.shodan_internetdb.check_ip, ip)
        if 'ip_api' in sources:
            results['ip_api'] = self._call('ip_api', self.ip_api.get_geolocation, ip)
        if 'censys' in sources:
            results['censys'] = self._call('censys', self.censys.check_ip, ip)
        if 'ipinfo' in sources:
            results['ipinfo'] = self._call('ipinfo', self.ipinfo.check_ip, ip)
        if 'urlhaus' in sources:
            results['urlhaus'] = self._call('urlhaus', self.urlhaus.check_host, ip)
        if 'threatfox' in sources:
            results['threatfox'] = self._call('threatfox', self.threatfox.search_ioc, ip)

        return results

    def analyze_domain(self, domain: str, sources: list = None) -> Dict:
        """Analiza un dominio en múltiples fuentes"""
        if sources is None:
            sources = ['virustotal', 'otx', 'securitytrails', 'safebrowsing',
                       'criminal_ip', 'pulsedive', 'urlscan']

        results = {}

        if 'virustotal' in sources:
            results['virustotal'] = self._call('virustotal', self.virustotal.check_domain, domain)
        if 'otx' in sources:
            results['otx'] = self._call('otx', self.otx.check_domain, domain)
        if 'securitytrails' in sources:
            results['securitytrails'] = self._call('securitytrails', self.securitytrails.get_domain_details, domain)
        if 'safebrowsing' in sources:
            results['safebrowsing'] = self._call('google_safebrowsing', self.safebrowsing.check_url, f"http://{domain}")
        if 'criminal_ip' in sources:
            results['criminal_ip'] = self._call('criminal_ip', self.criminal_ip.check_domain, domain)
        if 'pulsedive' in sources:
            results['pulsedive'] = self._call('pulsedive', self.pulsedive.get_indicator, domain)
        if 'urlscan' in sources:
            results['urlscan'] = self._call('urlscan', self.urlscan.search, f"domain:{domain}")
        if 'urlhaus' in sources:
            results['urlhaus'] = self._call('urlhaus', self.urlhaus.check_host, domain)
        if 'threatfox' in sources:
            results['threatfox'] = self._call('threatfox', self.threatfox.search_ioc, domain)

        return results

    def analyze_hash(self, file_hash: str, sources: list = None) -> Dict:
        """Analiza un hash en múltiples fuentes"""
        if sources is None:
            sources = ['virustotal', 'hybrid_analysis', 'malwarebazaar', 'otx', 'pulsedive']

        results = {}

        if 'virustotal' in sources:
            results['virustotal'] = self._call('virustotal', self.virustotal.check_hash, file_hash)
        if 'hybrid_analysis' in sources:
            results['hybrid_analysis'] = self._call('hybrid_analysis', self.hybrid_analysis.search_hash, file_hash)
        if 'malwarebazaar' in sources:
            results['malwarebazaar'] = self._call('malwarebazaar', self.malwarebazaar.query_hash, file_hash)
        if 'otx' in sources:
            results['otx'] = self._call('otx', self.otx.check_hash, file_hash)
        if 'pulsedive' in sources:
            results['pulsedive'] = self._call('pulsedive', self.pulsedive.get_indicator, file_hash)
        if 'threatfox' in sources:
            results['threatfox'] = self._call('threatfox', self.threatfox.search_ioc, file_hash)

        return results

    def analyze_url(self, url: str, sources: list = None) -> Dict:
        """Analiza una URL en múltiples fuentes"""
        if sources is None:
            sources = ['safebrowsing', 'urlhaus', 'urlscan', 'pulsedive']

        results = {}

        if 'safebrowsing' in sources:
            results['safebrowsing'] = self._call('google_safebrowsing', self.safebrowsing.check_url, url)
        if 'urlhaus' in sources:
            results['urlhaus'] = self._call('urlhaus', self.urlhaus.check_url, url)
        if 'urlscan' in sources:
            results['urlscan'] = self._call('urlscan', self.urlscan.search, f'url:"{url}"')
        if 'pulsedive' in sources:
            results['pulsedive'] = self._call('pulsedive', self.pulsedive.get_indicator, url)
        if 'threatfox' in sources:
            results['threatfox'] = self._call('threatfox', self.threatfox.search_ioc, url)

        return results