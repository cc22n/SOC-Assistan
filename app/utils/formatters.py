"""
Formateadores para respuestas y reportes
"""
from typing import Dict
from datetime import datetime


def format_analysis_response(results: Dict, analysis_id: int = None) -> Dict:
    """
    Formatea la respuesta del análisis para la API

    Args:
        results: Resultados del análisis
        analysis_id: ID del análisis en BD (opcional)

    Returns:
        Dict formateado para respuesta
    """
    response = {
        'id': analysis_id,
        'ioc': results.get('ioc'),
        'type': results.get('type'),
        'confidence_score': results.get('confidence_score', 0),
        'risk_level': results.get('risk_level', 'UNKNOWN'),
        'recommendation': results.get('recommendation', ''),
        'timestamp': datetime.utcnow().isoformat(),
        'sources': {}
    }

    # VirusTotal
    if results.get('virustotal') and 'error' not in results['virustotal']:
        vt = results['virustotal']
        response['sources']['virustotal'] = {
            'status': 'success',
            'detection_ratio': vt.get('detection_ratio', '0/0'),
            'positives': vt.get('positive_detections', 0),
            'total': vt.get('total_scans', 0),
            'malware_families': vt.get('malware_families', [])[:5]
        }

    # AbuseIPDB
    if results.get('abuseipdb') and 'error' not in results['abuseipdb']:
        abuse = results['abuseipdb']
        response['sources']['abuseipdb'] = {
            'status': 'success',
            'confidence': abuse.get('abuse_confidence', 0),
            'reports': abuse.get('total_reports', 0),
            'country': abuse.get('country', 'Unknown')
        }

    # Shodan
    if results.get('shodan') and 'error' not in results['shodan']:
        shodan = results['shodan']
        response['sources']['shodan'] = {
            'status': 'success',
            'ports': shodan.get('ports', [])[:5],
            'services': shodan.get('services', [])[:5],
            'dangerous_services': shodan.get('dangerous_services', []),
            'vulnerabilities_count': len(shodan.get('vulnerabilities', []))
        }

    # OTX
    if results.get('otx'):
        otx = results['otx']
        otx_data = {}

        if 'general' in otx and 'error' not in otx['general']:
            otx_data['pulse_count'] = otx['general'].get('pulse_count', 0)
            otx_data['pulses'] = otx['general'].get('pulses', [])[:3]

        if 'reputation' in otx and 'error' not in otx['reputation']:
            otx_data['reputation'] = otx['reputation'].get('reputation', 0)

        if otx_data:
            response['sources']['otx'] = {
                'status': 'success',
                **otx_data
            }

    # MITRE ATT&CK
    if results.get('mitre_techniques'):
        response['mitre_attack'] = {
            'techniques_count': len(results['mitre_techniques']),
            'techniques': results['mitre_techniques'][:5],
            'tactics': list(set([t['tactic'] for t in results['mitre_techniques']]))
        }

    # LLM Analysis
    if results.get('llm_analysis') and 'error' not in results['llm_analysis']:
        response['ai_analysis'] = results['llm_analysis']

    # Errores
    if results.get('errors'):
        response['warnings'] = results['errors']

    # Incident
    if results.get('incident'):
        response['incident'] = results['incident']

    return response


def format_incident_ticket(results: Dict, analysis_id: int = None) -> str:
    """
    Genera un ticket de incidente en formato texto

    Args:
        results: Resultados del análisis
        analysis_id: ID del análisis

    Returns:
        String con el ticket formateado
    """
    confidence = results.get('confidence_score', 0)

    # Determinar prioridad
    if confidence >= 70:
        priority = "P1"
        urgency = "CRÍTICO"
    elif confidence >= 50:
        priority = "P2"
        urgency = "ALTO"
    elif confidence >= 30:
        priority = "P3"
        urgency = "MEDIO"
    else:
        priority = "P4"
        urgency = "BAJO"

    # Generar ticket ID
    timestamp = datetime.now().strftime('%Y%m%d')
    ticket_id = f"SOC-{timestamp}-{analysis_id or 0:05d}"

    ticket = f"""
╔══════════════════════════════════════════════════════════════╗
║            TICKET DE INCIDENTE SOC                           ║
╚══════════════════════════════════════════════════════════════╝

INFORMACIÓN BÁSICA
─────────────────────────────────────────────────────────────
  Ticket ID:     {ticket_id}
  Fecha:         {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  Prioridad:     {priority} - {urgency}
  Analista:      Sistema Automatizado

IOC ANALIZADO
─────────────────────────────────────────────────────────────
  Tipo:          {results.get('type', 'unknown').upper()}
  Valor:         {results.get('ioc', 'unknown')}
  Confianza:     {confidence}/100
  Nivel Riesgo:  {results.get('risk_level', 'UNKNOWN')}

EVIDENCIA CORRELACIONADA
─────────────────────────────────────────────────────────────"""

    # VirusTotal
    if results.get('virustotal') and 'positive_detections' in results['virustotal']:
        vt = results['virustotal']
        ticket += f"""
  ✓ VirusTotal:  {vt['detection_ratio']} detecciones"""
        if vt.get('malware_families'):
            ticket += f"""
                 Familias: {', '.join(vt['malware_families'][:3])}"""

    # AbuseIPDB
    if results.get('abuseipdb') and 'abuse_confidence' in results['abuseipdb']:
        abuse = results['abuseipdb']
        ticket += f"""
  ✓ AbuseIPDB:   {abuse['abuse_confidence']}% confianza
                 {abuse['total_reports']} reportes"""

    # Shodan
    if results.get('shodan') and 'dangerous_services' in results['shodan']:
        shodan = results['shodan']
        if shodan['dangerous_services']:
            ticket += f"""
  ✓ Shodan:      Servicios peligrosos detectados
                 {', '.join(shodan['dangerous_services'][:3])}"""

    # OTX
    if results.get('otx') and 'general' in results['otx']:
        pulse_count = results['otx']['general'].get('pulse_count', 0)
        if pulse_count > 0:
            ticket += f"""
  ✓ OTX:         {pulse_count} pulsos de threat intelligence"""

    # MITRE
    if results.get('mitre_techniques'):
        techniques = results['mitre_techniques']
        ticket += f"""
  ✓ MITRE:       {len(techniques)} técnicas identificadas"""
        for tech in techniques[:3]:
            ticket += f"""
                 - {tech['id']}: {tech['name']}"""

    ticket += f"""

RECOMENDACIÓN
─────────────────────────────────────────────────────────────
{results.get('recommendation', 'No disponible')}

PRÓXIMOS PASOS
─────────────────────────────────────────────────────────────
  1. Revisar logs relacionados en SIEM
  2. Verificar sistemas afectados
  3. Implementar bloqueos según prioridad
  4. Documentar en base de conocimiento
  5. Generar métricas de detección

FUENTES CONSULTADAS
─────────────────────────────────────────────────────────────
  VirusTotal, AbuseIPDB, Shodan, AlienVault OTX, MITRE ATT&CK

╔══════════════════════════════════════════════════════════════╗
║  FIN DEL TICKET - {ticket_id}  ║
╚══════════════════════════════════════════════════════════════╝
"""

    return ticket


def format_summary_report(analyses: list) -> str:
    """
    Genera un reporte resumen de múltiples análisis

    Args:
        analyses: Lista de resultados de análisis

    Returns:
        String con reporte formateado
    """
    if not analyses:
        return "No hay análisis disponibles"

    total = len(analyses)
    critical = sum(1 for a in analyses if a.get('confidence_score', 0) >= 70)
    high = sum(1 for a in analyses if 50 <= a.get('confidence_score', 0) < 70)
    medium = sum(1 for a in analyses if 30 <= a.get('confidence_score', 0) < 50)
    low = sum(1 for a in analyses if a.get('confidence_score', 0) < 30)

    report = f"""
╔══════════════════════════════════════════════════════════════╗
║            REPORTE RESUMEN DE ANÁLISIS SOC                   ║
╚══════════════════════════════════════════════════════════════╝

Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

ESTADÍSTICAS GENERALES
─────────────────────────────────────────────────────────────
  Total Análisis:     {total}

  ⚠️  Crítico:         {critical} ({critical / total * 100:.1f}%)
  🔴 Alto:            {high} ({high / total * 100:.1f}%)
  🟡 Medio:           {medium} ({medium / total * 100:.1f}%)
  🟢 Bajo:            {low} ({low / total * 100:.1f}%)

ANÁLISIS INDIVIDUALES
─────────────────────────────────────────────────────────────
"""

    for i, analysis in enumerate(analyses[:10], 1):
        risk_emoji = {
            'CRÍTICO': '⚠️',
            'ALTO': '🔴',
            'MEDIO': '🟡',
            'BAJO': '🟢',
            'LIMPIO': '✅'
        }.get(analysis.get('risk_level', 'UNKNOWN'), '❓')

        report += f"""
{i}. {risk_emoji} {analysis.get('type', 'unknown').upper()}: {analysis.get('ioc', 'unknown')[:50]}
   Score: {analysis.get('confidence_score', 0)}/100 | Riesgo: {analysis.get('risk_level', 'UNKNOWN')}
"""

    if len(analyses) > 10:
        report += f"\n... y {len(analyses) - 10} análisis más\n"

    report += """
╚══════════════════════════════════════════════════════════════╝
"""

    return report