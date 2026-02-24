"""
Base de datos MITRE ATT&CK
Mapeo de técnicas y tácticas
"""

# Base de datos de técnicas MITRE ATT&CK
MITRE_TECHNIQUES_DB = {
    # Initial Access
    'T1566.001': {'name': 'Spearphishing Attachment', 'tactic': 'Initial Access'},
    'T1566.002': {'name': 'Spearphishing Link', 'tactic': 'Initial Access'},
    'T1190': {'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access'},
    'T1078': {'name': 'Valid Accounts', 'tactic': 'Initial Access'},
    'T1133': {'name': 'External Remote Services', 'tactic': 'Initial Access'},

    # Execution
    'T1059.001': {'name': 'PowerShell', 'tactic': 'Execution'},
    'T1059.003': {'name': 'Windows Command Shell', 'tactic': 'Execution'},
    'T1059.005': {'name': 'Visual Basic', 'tactic': 'Execution'},
    'T1204.002': {'name': 'Malicious File', 'tactic': 'Execution'},
    'T1053.005': {'name': 'Scheduled Task', 'tactic': 'Execution'},

    # Persistence
    'T1547.001': {'name': 'Registry Run Keys', 'tactic': 'Persistence'},
    'T1543.003': {'name': 'Windows Service', 'tactic': 'Persistence'},
    'T1136.001': {'name': 'Local Account', 'tactic': 'Persistence'},

    # Defense Evasion
    'T1055': {'name': 'Process Injection', 'tactic': 'Defense Evasion'},
    'T1027': {'name': 'Obfuscated Files or Information', 'tactic': 'Defense Evasion'},
    'T1036': {'name': 'Masquerading', 'tactic': 'Defense Evasion'},
    'T1070': {'name': 'Indicator Removal', 'tactic': 'Defense Evasion'},
    'T1140': {'name': 'Deobfuscate/Decode Files', 'tactic': 'Defense Evasion'},
    'T1562.001': {'name': 'Disable or Modify Tools', 'tactic': 'Defense Evasion'},

    # Credential Access
    'T1003.001': {'name': 'LSASS Memory', 'tactic': 'Credential Access'},
    'T1003.002': {'name': 'Security Account Manager', 'tactic': 'Credential Access'},
    'T1110.001': {'name': 'Password Guessing', 'tactic': 'Credential Access'},
    'T1110.003': {'name': 'Password Spraying', 'tactic': 'Credential Access'},
    'T1056.001': {'name': 'Keylogging', 'tactic': 'Credential Access'},

    # Discovery
    'T1082': {'name': 'System Information Discovery', 'tactic': 'Discovery'},
    'T1083': {'name': 'File and Directory Discovery', 'tactic': 'Discovery'},
    'T1135': {'name': 'Network Share Discovery', 'tactic': 'Discovery'},

    # Lateral Movement
    'T1021.001': {'name': 'Remote Desktop Protocol', 'tactic': 'Lateral Movement'},
    'T1021.002': {'name': 'SMB/Windows Admin Shares', 'tactic': 'Lateral Movement'},

    # Collection
    'T1005': {'name': 'Data from Local System', 'tactic': 'Collection'},
    'T1039': {'name': 'Data from Network Shared Drive', 'tactic': 'Collection'},

    # Command and Control
    'T1071.001': {'name': 'Web Protocols', 'tactic': 'Command and Control'},
    'T1090': {'name': 'Proxy', 'tactic': 'Command and Control'},
    'T1573': {'name': 'Encrypted Channel', 'tactic': 'Command and Control'},
    'T1105': {'name': 'Ingress Tool Transfer', 'tactic': 'Command and Control'},

    # Exfiltration
    'T1041': {'name': 'Exfiltration Over C2 Channel', 'tactic': 'Exfiltration'},
    'T1048': {'name': 'Exfiltration Over Alternative Protocol', 'tactic': 'Exfiltration'},

    # Impact
    'T1486': {'name': 'Data Encrypted for Impact', 'tactic': 'Impact'},
    'T1489': {'name': 'Service Stop', 'tactic': 'Impact'},
    'T1490': {'name': 'Inhibit System Recovery', 'tactic': 'Impact'},
    'T1561': {'name': 'Disk Wipe', 'tactic': 'Impact'},
}

# Mapeo de familias de malware a técnicas ATT&CK
MALWARE_TO_TECHNIQUES = {
    # Banking Trojans
    'trickbot': ['T1566.001', 'T1055', 'T1071.001', 'T1056.001', 'T1003.001'],
    'emotet': ['T1566.001', 'T1059.003', 'T1055', 'T1027', 'T1105'],
    'dridex': ['T1566.001', 'T1055', 'T1071.001', 'T1056.001'],
    'zeus': ['T1056.001', 'T1082', 'T1071.001', 'T1055'],
    'banker': ['T1056.001', 'T1082', 'T1071.001'],

    # APT Tools
    'cobalt': ['T1055', 'T1071.001', 'T1090', 'T1059.001', 'T1105'],
    'metasploit': ['T1055', 'T1071.001', 'T1090', 'T1059.001'],
    'empire': ['T1059.001', 'T1055', 'T1071.001'],

    # Ransomware
    'ransomware': ['T1486', 'T1490', 'T1489', 'T1070', 'T1562.001'],
    'wannacry': ['T1486', 'T1190', 'T1489', 'T1070'],
    'ryuk': ['T1486', 'T1490', 'T1489', 'T1070'],
    'lockbit': ['T1486', 'T1490', 'T1489', 'T1562.001'],
    'conti': ['T1486', 'T1490', 'T1489', 'T1070'],

    # Generic Malware Types
    'trojan': ['T1055', 'T1027', 'T1204.002', 'T1547.001'],
    'backdoor': ['T1071.001', 'T1090', 'T1055', 'T1078', 'T1133'],
    'botnet': ['T1071.001', 'T1090', 'T1059.001', 'T1105', 'T1110.003'],
    'rat': ['T1071.001', 'T1056.001', 'T1105'],
    'spyware': ['T1056.001', 'T1082'],
    'rootkit': ['T1055', 'T1027', 'T1036', 'T1070', 'T1562.001'],
    'worm': ['T1082', 'T1135'],
    'virus': ['T1055', 'T1027', 'T1204.002', 'T1140'],
    'malware': ['T1055', 'T1027', 'T1204.002'],

    # Phishing
    'phishing': ['T1566.001', 'T1566.002', 'T1204.002'],

    # Droppers/Loaders
    'downloader': ['T1105', 'T1071.001', 'T1204.002'],
    'dropper': ['T1105', 'T1055', 'T1204.002'],
    'loader': ['T1105', 'T1055', 'T1027'],

    # Stealers
    'stealer': ['T1056.001', 'T1071.001', 'T1005'],
    'infostealer': ['T1056.001', 'T1005', 'T1041'],

    # Miners
    'miner': ['T1496', 'T1055', 'T1027'],
    'cryptominer': ['T1496', 'T1055'],

    # Specific Malware Families
    'mirai': ['T1110.001', 'T1133', 'T1071.001'],
    'solarwinds': ['T1195.002', 'T1078', 'T1071.001'],
    'darkside': ['T1486', 'T1490', 'T1041'],
    'revil': ['T1486', 'T1490', 'T1489'],
}

# Tácticas MITRE ATT&CK en orden de la kill chain
MITRE_TACTICS = [
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Escalation',
    'Defense Evasion',
    'Credential Access',
    'Discovery',
    'Lateral Movement',
    'Collection',
    'Command and Control',
    'Exfiltration',
    'Impact'
]

# Niveles de severidad por táctica
TACTIC_SEVERITY = {
    'Initial Access': 'HIGH',
    'Execution': 'CRITICAL',
    'Persistence': 'HIGH',
    'Privilege Escalation': 'CRITICAL',
    'Defense Evasion': 'MEDIUM',
    'Credential Access': 'CRITICAL',
    'Discovery': 'LOW',
    'Lateral Movement': 'HIGH',
    'Collection': 'MEDIUM',
    'Command and Control': 'HIGH',
    'Exfiltration': 'CRITICAL',
    'Impact': 'CRITICAL'
}


def get_technique_info(technique_id: str) -> dict:
    """
    Obtiene información de una técnica MITRE

    Args:
        technique_id: ID de la técnica (ej: 'T1566.001')

    Returns:
        Dict con información de la técnica
    """
    return MITRE_TECHNIQUES_DB.get(technique_id, {
        'name': 'Unknown Technique',
        'tactic': 'Unknown'
    })


def get_techniques_by_malware(malware_name: str) -> list:
    """
    Obtiene técnicas asociadas a una familia de malware

    Args:
        malware_name: Nombre de la familia de malware

    Returns:
        Lista de IDs de técnicas
    """
    malware_lower = malware_name.lower()

    for key, techniques in MALWARE_TO_TECHNIQUES.items():
        if key in malware_lower:
            return techniques

    return []


def get_techniques_by_tactic(tactic: str) -> list:
    """
    Obtiene todas las técnicas de una táctica específica

    Args:
        tactic: Nombre de la táctica

    Returns:
        Lista de técnicas
    """
    return [
        {'id': tid, **info}
        for tid, info in MITRE_TECHNIQUES_DB.items()
        if info['tactic'] == tactic
    ]