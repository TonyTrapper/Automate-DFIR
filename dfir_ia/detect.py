"""Detecciones deterministas; los hallazgos nunca se confunden con hechos confirmados."""
from __future__ import annotations
from collections import defaultdict
from datetime import timedelta
import re

LEVEL_ORDER = {'informational': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


def _finding(title, sev, category, description, recommendation, refs, indicators=None):
    return {'title': title, 'severity': sev, 'category': category,
            'description': description, 'recommendation': recommendation,
            'evidence': refs[:12], 'evidence_count': len(refs),
            'indicators': indicators or [], 'status': 'Pendiente de validación humana'}


def _text(e):
    return f'{e.title} | {e.details}'.lower()


def _ip_field(t):
    for pattern in (r'(?:source\s*network\s*address|sourceip|ipaddress|srcip|src_ip|ip de origen|ip)\s*[:=：]\s*(\d{1,3}(?:\.\d{1,3}){3})',
                    r'\b(?:(?:\d{1,3}\.){3}\d{1,3})\b'):
        m = re.search(pattern, t, flags=re.I)
        if m:
            value = m.group(1) if m.lastindex else m.group(0)
            if value not in {'0.0.0.0', '127.0.0.1'} and all(int(x) <= 255 for x in value.split('.')):
                return value
    return None


def detect(events, snapshots):
    findings = []
    # Hayabusa already detected suspicious patterns. We preserve its detection provenance.
    for e in events:
        t = _text(e)
        ref = e.ref()
        eid = e.event_id.strip()
        if eid == '4104' and (('get.activated.win' in t) or re.search(r'\b(?:irm|iwr|invoke-restmethod|invoke-webrequest)\b.{0,150}\|\s*(?:iex|invoke-expression)\b', t)):
            findings.append(_finding('PowerShell: descarga y ejecución directa', 'high', 'Ejecución',
                'El evento contiene un patrón de descarga de contenido y ejecución mediante PowerShell. No acredita por sí solo infección.',
                'Reconstruir script y árbol de procesos; revisar origen, usuario y efectos posteriores.', [ref], ['PowerShell 4104', 'download-to-execute']))
        elif eid == '4104' and re.search(r'\b(?:-enc|-encodedcommand|frombase64string)\b', t):
            findings.append(_finding('PowerShell con codificación', 'medium', 'Ejecución',
                'Se observó codificación de comandos; también puede existir uso administrativo legítimo.',
                'Decodificar contenido y corroborar comando, contexto y proceso padre.', [ref], ['PowerShell 4104']))
        if eid == '5007' and ('defender' in e.channel.lower() or 'defender' in t):
            findings.append(_finding('Cambio de configuración de Microsoft Defender', 'medium', 'Configuración',
                'Se registró una modificación de Defender. El evento por sí mismo no determina el efecto ni su autor.',
                'Comparar valores anterior/nuevo y correlacionar con cambios autorizados.', [ref], ['Defender 5007']))
        if eid == '1102':
            findings.append(_finding('Borrado del registro de seguridad', 'high', 'Antiforense',
                'Se registró limpieza del registro Security; requiere determinar actor y justificación.',
                'Preservar copias existentes, revisar administración y otras fuentes de registro.', [ref], ['Windows 1102']))
        if eid == '7045' or eid == '4697':
            findings.append(_finding('Instalación de servicio Windows', 'medium', 'Persistencia',
                'Se instaló un servicio; puede corresponder a una instalación legítima o persistencia.',
                'Validar binario, ruta, firma, cuenta, fecha y orden de cambio.', [ref], ['Windows 7045/4697']))
        if eid == '4698':
            findings.append(_finding('Creación de tarea programada', 'medium', 'Persistencia',
                'Se creó una tarea programada; requiere revisar acción, desencadenadores y autor.',
                'Verificar XML/acción de la tarea y compararlo con inventario y cambios aprobados.', [ref], ['Windows 4698']))
        if eid == '4720':
            findings.append(_finding('Creación de cuenta Windows', 'medium', 'Identidad',
                'Se registró una cuenta nueva. No implica escalada hasta comprobar privilegios.',
                'Identificar creador, grupo inicial y autorización del alta.', [ref], ['Windows 4720']))
        if eid == '4732' and re.search(r'\badministrators\b|\badministradores\b', t):
            findings.append(_finding('Cambio en grupo local Administrators', 'high', 'Identidad',
                'Se registró adición de miembro a un grupo de administradores.',
                'Verificar SID, identidad de la cuenta, actor y ticket de autorización.', [ref], ['Windows 4732']))
        if e.title and e.level.lower() in {'high', 'critical'} and e.rule_id:
            findings.append(_finding('Detección Hayabusa: ' + e.title[:120],
                e.level.lower(), 'Detección de terceros',
                'Coincidencia de regla de Hayabusa; es un indicador que requiere validación independiente.',
                'Inspeccionar la regla original, evento y posibles falsos positivos.', [ref], [f'Regla {e.rule_id}']))

    # Aggregate 4625 brute-force candidates by host + extracted IP and a rolling 5min window.
    auth = defaultdict(list)
    for e in events:
        if e.event_id.strip() == '4625' and e.dt:
            ip = _ip_field(e.details)
            if ip:
                auth[(e.computer, ip)].append(e)
    for (host, ip), group in auth.items():
        group.sort(key=lambda e: e.dt)
        i = 0
        while i < len(group):
            j = i
            while j < len(group) and group[j].dt - group[i].dt <= timedelta(minutes=5):
                j += 1
            if j - i >= 5:
                refs = [e.ref() for e in group[i:j]]
                findings.append(_finding('Múltiples autenticaciones fallidas desde una IP', 'medium', 'Autenticación',
                    f'Se observaron {j-i} eventos 4625 del host {host} asociados a {ip} en hasta 5 minutos. La IP se extrajo del contenido y debe validarse.',
                    'Verificar cuentas, tipo de logon, error y accesos posteriores; descartar credenciales desactualizadas.',
                    refs, ['Windows 4625', ip]))
                i = j
            else:
                i += 1

    # A correlation signals temporal proximity, NEVER causality.
    by_host = defaultdict(list)
    for e in events:
        if e.dt:
            by_host[e.computer].append(e)
    for host, group in by_host.items():
        scripts = [e for e in group if e.event_id.strip() == '4104' and 'get.activated.win' in _text(e)]
        changes = [e for e in group if e.event_id.strip() == '5007']
        matched = []
        for a in scripts:
            for b in changes:
                if abs((a.dt - b.dt).total_seconds()) <= 15 * 60:
                    matched.extend([a.ref(), b.ref()])
        if matched:
            findings.append(_finding('Proximidad temporal: PowerShell y cambio de Defender', 'high', 'Correlación',
                f'Se detectaron eventos 4104 y 5007 próximos en el tiempo en {host}. La proximidad no demuestra relación causal.',
                'Comparar identidad, secuencia de procesos y contenido exacto de los cambios.',
                matched, ['4104', '5007', 'ventana 15 min']))

    # Snapshot is present-time configuration, not an execution or historical timeline record.
    for snap, source in snapshots:
        if not isinstance(snap, dict):
            continue
        host = str(snap.get('Hostname') or snap.get('Computer') or 'DESCONOCIDO')
        snapref = {'source': source, 'timestamp': str(snap.get('CollectedUTC', '')),
                   'computer': host, 'event_id': 'SNAPSHOT', 'record_id': '', 'hayabusa_rule_id': ''}
        autologon = snap.get('AutoAdminLogon')
        if str(autologon) == '1':
            findings.append(_finding('AutoAdminLogon habilitado', 'medium', 'Configuración',
                'La instantánea actual registra AutoAdminLogon=1; no establece cuándo fue activado.',
                'Evaluar necesidad, revisar almacenamiento de credenciales sin extraer contraseñas y deshabilitar si no procede.',
                [snapref], ['AutoAdminLogon=1']))
        for profile in snap.get('Firewall', []) or []:
            if isinstance(profile, dict) and str(profile.get('Enabled', '')).lower() in {'false', '0'}:
                name = str(profile.get('Name', '?'))
                findings.append(_finding(f'Firewall deshabilitado: {name}', 'medium', 'Configuración',
                    f'El perfil {name} aparece deshabilitado en la instantánea actual.',
                    'Validar perfil y políticas; habilitar según la configuración corporativa autorizada.',
                    [snapref], ['Windows Firewall']))
        defender = snap.get('Defender') or {}
        if isinstance(defender, dict):
            for key in ('ExclusionPath', 'ExclusionProcess', 'ExclusionExtension'):
                values = defender.get(key) or []
                if isinstance(values, str):
                    values = [values]
                for exclusion in values[:150]:
                    findings.append(_finding(f'Exclusión de Defender: {key}', 'low', 'Configuración',
                        f'La instantánea incluye una exclusión de tipo {key}: {str(exclusion)[:180]}. No implica actividad maliciosa.',
                        'Revisar justificación, alcance y si puede retirarse; confirmar con el administrador del equipo.',
                        [snapref], [str(exclusion)[:180]]))
            if str(defender.get('RealTimeProtectionEnabled', '')).lower() in {'false', '0'}:
                findings.append(_finding('Protección en tiempo real deshabilitada', 'high', 'Configuración',
                    'El estado de Defender registra protección en tiempo real deshabilitada al recopilar la instantánea.',
                    'Comprobar si otro antivirus gestiona la protección; revisar política y eventos de cambio.',
                    [snapref], ['Defender RealTimeProtectionEnabled=False']))

    # Merge only identical titles/categories on the same computer and source grouping, preserving counts.
    merged = {}
    for f in findings:
        first = f['evidence'][0] if f['evidence'] else {}
        key = (f['title'], f['category'], first.get('computer', ''))
        if key not in merged:
            merged[key] = f
        else:
            prev = merged[key]
            prev['evidence_count'] += f['evidence_count']
            prev['evidence'] = (prev['evidence'] + f['evidence'])[:12]
    result = sorted(merged.values(), key=lambda f: (-LEVEL_ORDER.get(f['severity'], 0), f['title']))
    for idx, item in enumerate(result, 1):
        item['id'] = f'DFIR-{idx:03}'
    return result
