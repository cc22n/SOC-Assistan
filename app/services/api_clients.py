"""
Clientes de API refactorizados para arquitectura Flask
"""
import requests
import logging
from typing import Dict, Optional
from flask import current_app
from app.models.ioc import APIUsage
from app import db
from datetime import datetime

logger = logging.getLogger(__name__)


class APIClient:
    """Clase base para clientes de API"""

    def __init__(self, api_name: str):
        self.api_name = api_name
        self.api_key = current_app.config['API_KEYS'].get(api_name)
        self.daily_limit = current_app.config['API_LIMITS'].get(api_name, 1000)
        self.session = requests.Session()
        self.session.timeout = 15

    def _check_rate_limit(self) -> bool:
        """Verifica límite diario desde BD"""
        today = datetime.utcnow().date()
        usage = APIUsage.query.filter_by(
            api_name=self.api_name,
            date=today
        ).first()

        if not usage:
            return False

        return usage.requests_count >= self.daily_limit

    def _increment_requests(self, is_error=False):
        """Incrementa contador en BD"""
        from flask import current_app

        # Verificar si estamos en contexto de aplicación
        if not current_app:
            return

        today = datetime.utcnow().date()
        usage = APIUsage.query.filter_by(
            api_name=self.api_name,
            date=today
        ).first()

        if not usage:
            usage = APIUsage(
                api_name=self.api_name,
                date=today,
                requests_count=0,
                errors_count=0
            )
            db.session.add(usage)

        usage.requests_count += 1
        if is_error:
            usage.errors_count += 1

        try:
            db.session.commit()
        except Exception as e:
            logger.error(f"Error updating API usage: {e}")
            db.session.rollback()

    def _handle_error(self, error: Exception, context: str = "") -> Dict:
        """Manejo centralizado de errores"""
        error_msg = f"{self.api_name.upper()} Error"
        if context:
            error_msg += f" ({context})"
        error_msg += f": {str(error)}"

        logger.error(error_msg)
        self._increment_requests(is_error=True)

        return {'error': error_msg}


class VirusTotalClient(APIClient):
    """Cliente para VirusTotal API v2"""

    def __init__(self):
        super().__init__('virustotal')
        self.base_url = "https://www.virustotal.com/vtapi/v2"

    def check_ioc(self, ioc: str, ioc_type: str) -> Dict:
        """Consulta IOC en VirusTotal"""
        if self._check_rate_limit():
            return {'error': f'Límite diario VT alcanzado ({self.daily_limit})'}

        if not self.api_key:
            return {'error': 'API key de VirusTotal no configurada'}

        endpoints = {
            'hash': f"{self.base_url}/file/report",
            'ip': f"{self.base_url}/ip-address/report",
            'domain': f"{self.base_url}/domain/report",
            'url': f"{self.base_url}/url/report"
        }

        if ioc_type not in endpoints:
            return {'error': f'Tipo de IOC no soportado: {ioc_type}'}

        params = {'apikey': self.api_key}
        if ioc_type == 'hash':
            params['resource'] = ioc
        elif ioc_type == 'ip':
            params['ip'] = ioc
        elif ioc_type == 'domain':
            params['domain'] = ioc
        elif ioc_type == 'url':
            params['resource'] = ioc

        try:
            response = self.session.get(endpoints[ioc_type], params=params)
            self._increment_requests()

            if response.status_code == 200:
                data = response.json()
                if data.get('response_code') == 1:
                    return self._parse_vt_response(data, ioc_type)
                elif data.get('response_code') == 0:
                    return {'error': 'IOC no encontrado en VirusTotal'}
                else:
                    return {'error': f'VT response code: {data.get("response_code")}'}
            else:
                return {'error': f'VT HTTP {response.status_code}'}

        except Exception as e:
            return self._handle_error(e, "check_ioc")

    def _parse_vt_response(self, data: Dict, ioc_type: str) -> Dict:
        """Parse respuesta de VirusTotal"""
        result = {
            'scan_date': data.get('scan_date', 'Unknown'),
            'positive_detections': data.get('positives', 0),
            'total_scans': data.get('total', 0),
            'malware_families': [],
            'engines_detected': []
        }

        # Extraer familias de malware
        scans = data.get('scans', {})
        for engine, details in scans.items():
            if details and details.get('detected') and details.get('result'):
                family = details['result'].split('.')[0].split('/')[0].lower()
                if family and family not in result['malware_families']:
                    result['malware_families'].append(family)
                result['engines_detected'].append({
                    'engine': engine,
                    'result': details['result']
                })

        result['detection_ratio'] = f"{result['positive_detections']}/{result['total_scans']}"
        return result


class AbuseIPDBClient(APIClient):
    """Cliente para AbuseIPDB"""

    def __init__(self):
        super().__init__('abuseipdb')
        self.base_url = "https://api.abuseipdb.com/api/v2"

    def check_ip(self, ip: str) -> Dict:
        """Consulta IP en AbuseIPDB"""
        if self._check_rate_limit():
            return {'error': f'Límite diario AbuseIPDB alcanzado ({self.daily_limit})'}

        if not self.api_key:
            return {'error': 'API key de AbuseIPDB no configurada'}

        headers = {'Key': self.api_key, 'Accept': 'application/json'}
        url = f"{self.base_url}/check"
        params = {'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': ''}

        try:
            response = self.session.get(url, headers=headers, params=params)
            self._increment_requests()

            if response.status_code == 200:
                data = response.json()
                if 'data' in data:
                    return {
                        'abuse_confidence': data['data'].get('abuseConfidencePercentage', 0),
                        'country': data['data'].get('countryCode', 'Unknown'),
                        'usage_type': data['data'].get('usageType', 'Unknown'),
                        'isp': data['data'].get('isp', 'Unknown'),
                        'total_reports': data['data'].get('totalReports', 0),
                        'is_whitelisted': data['data'].get('isWhitelisted', False)
                    }
                else:
                    return {'error': 'Respuesta AbuseIPDB sin datos'}
            else:
                return {'error': f'AbuseIPDB HTTP {response.status_code}'}

        except Exception as e:
            return self._handle_error(e, "check_ip")


class ShodanClient(APIClient):
    """Cliente para Shodan"""

    def __init__(self):
        super().__init__('shodan')
        self.base_url = "https://api.shodan.io"

    def search_ip(self, ip: str) -> Dict:
        """Consulta información de IP en Shodan"""
        if self._check_rate_limit():
            return {'error': f'Límite diario Shodan alcanzado ({self.daily_limit})'}

        if not self.api_key:
            return {'error': 'API key de Shodan no configurada'}

        url = f"{self.base_url}/shodan/host/{ip}"
        params = {'key': self.api_key}

        try:
            response = self.session.get(url, params=params)
            self._increment_requests()

            if response.status_code == 200:
                data = response.json()
                return self._parse_shodan_response(data)
            elif response.status_code == 404:
                return {'error': 'IP no encontrada en Shodan'}
            else:
                return {'error': f'Shodan HTTP {response.status_code}'}

        except Exception as e:
            return self._handle_error(e, "search_ip")

    def _parse_shodan_response(self, data: Dict) -> Dict:
        """Parsea respuesta de Shodan"""
        ports = [item.get('port', 'Unknown') for item in data.get('data', [])]
        services = list(set([item.get('product', 'Unknown')
                             for item in data.get('data', []) if item.get('product')]))

        # Detectar servicios peligrosos
        dangerous_services = ['vnc', 'rdp', 'ssh', 'telnet', 'ftp',
                              'mysql', 'postgresql', 'mongodb']
        found_dangerous = [svc for svc in services
                           if any(danger in svc.lower() for danger in dangerous_services)]

        return {
            'ip': data.get('ip_str', ''),
            'country': data.get('country_name', 'Unknown'),
            'city': data.get('city', 'Unknown'),
            'isp': data.get('isp', 'Unknown'),
            'organization': data.get('org', 'Unknown'),
            'ports': ports[:10],
            'services': services[:10],
            'dangerous_services': found_dangerous,
            'hostnames': data.get('hostnames', []),
            'last_update': data.get('last_update', 'Unknown'),
            'vulnerabilities': data.get('vulns', [])
        }


class OTXClient(APIClient):
    """Cliente para AlienVault OTX"""

    def __init__(self):
        super().__init__('otx')
        self.base_url = "https://otx.alienvault.com/api/v1"

    def get_ip_reputation(self, ip: str) -> Dict:
        """Consulta reputación de IP en OTX"""
        if self._check_rate_limit():
            return {'error': f'Límite diario OTX alcanzado'}

        if not self.api_key:
            return {'error': 'API key de OTX no configurada'}

        headers = {'X-OTX-API-KEY': self.api_key}
        url = f"{self.base_url}/indicators/IPv4/{ip}/reputation"

        try:
            response = self.session.get(url, headers=headers)
            self._increment_requests()

            if response.status_code == 200:
                data = response.json()
                return {
                    'reputation': data.get('reputation', 0),
                    'threat_score': data.get('threat_score', 0),
                    'activities': data.get('activities', [])
                }
            else:
                return {'error': f'OTX HTTP {response.status_code}'}

        except Exception as e:
            return self._handle_error(e, "get_ip_reputation")

    def get_ip_general(self, ip: str) -> Dict:
        """Obtiene información general de IP"""
        if self._check_rate_limit():
            return {'error': 'Límite diario OTX alcanzado'}

        if not self.api_key:
            return {'error': 'API key de OTX no configurada'}

        headers = {'X-OTX-API-KEY': self.api_key}
        url = f"{self.base_url}/indicators/IPv4/{ip}/general"

        try:
            response = self.session.get(url, headers=headers)
            self._increment_requests()

            if response.status_code == 200:
                data = response.json()
                return {
                    'pulse_count': len(data.get('pulse_info', {}).get('pulses', [])),
                    'pulses': [p.get('name', 'Unknown')
                               for p in data.get('pulse_info', {}).get('pulses', [])[:5]],
                    'malware_families': data.get('malware', {}).get('data', []),
                    'base_indicator': data.get('base_indicator', {}),
                    'sections': list(data.get('sections', []))
                }
            else:
                return {'error': f'OTX General HTTP {response.status_code}'}

        except Exception as e:
            return self._handle_error(e, "get_ip_general")

    def get_domain_general(self, domain: str) -> Dict:
        """Obtiene información general de dominio"""
        if self._check_rate_limit():
            return {'error': 'Límite diario OTX alcanzado'}

        if not self.api_key:
            return {'error': 'API key de OTX no configurada'}

        headers = {'X-OTX-API-KEY': self.api_key}
        url = f"{self.base_url}/indicators/domain/{domain}/general"

        try:
            response = self.session.get(url, headers=headers)
            self._increment_requests()

            if response.status_code == 200:
                data = response.json()
                return {
                    'pulse_count': len(data.get('pulse_info', {}).get('pulses', [])),
                    'pulses': [p.get('name', 'Unknown')
                               for p in data.get('pulse_info', {}).get('pulses', [])[:5]],
                    'alexa_rank': data.get('alexa', 'Not ranked'),
                    'whois': data.get('whois', 'No whois data'),
                }
            else:
                return {'error': f'OTX Domain HTTP {response.status_code}'}

        except Exception as e:
            return self._handle_error(e, "get_domain_general")