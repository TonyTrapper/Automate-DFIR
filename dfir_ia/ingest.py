"""Ingesta de exportaciones Hayabusa CSV/JSON/JSONL y snapshots Windows (solo lectura)."""
from __future__ import annotations

import csv
import hashlib
import shutil
import io
import json
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone

MAX_ENTRY_BYTES = 250 * 1024 * 1024
SUPPORTED = {'.jsonl', '.ndjson', '.json', '.csv'}


@dataclass
class EvidenceEvent:
    timestamp: str
    computer: str
    event_id: str
    channel: str
    title: str
    details: str
    level: str
    source: str
    record_id: str = ''
    rule_id: str = ''
    raw: dict = field(default_factory=dict)

    @property
    def dt(self):
        t = self.timestamp.strip()
        if not t:
            return None
        # Hayabusa UTC or offset, also common CSV format YYYY-MM-DD HH:MM:SS.sss +00:00
        try:
            parsed = datetime.fromisoformat(t.replace('Z', '+00:00'))
            # El flujo recomendado exporta en UTC (-U). Si falta zona, se asume UTC.
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            return None

    def ref(self):
        return {'source': self.source, 'timestamp': self.timestamp, 'computer': self.computer,
                'event_id': self.event_id, 'record_id': self.record_id,
                'hayabusa_rule_id': self.rule_id}


def _get(row, *names):
    norm = {re.sub(r'[^a-z0-9]', '', str(k).lower()): v for k, v in row.items()}
    for name in names:
        value = norm.get(re.sub(r'[^a-z0-9]', '', name.lower()))
        if value is not None and str(value).strip():
            if isinstance(value, (dict, list)):
                return json.dumps(value, ensure_ascii=False, default=str)
            return str(value)
    return ''


def normalize(row, source):
    if not isinstance(row, dict):
        return None
    # A standalone JSON snapshot is parsed separately.
    if 'security_snapshot' in row or 'SecuritySnapshot' in row:
        return None
    if not any(_get(row, k) for k in ('EventID', 'EventId', 'Event ID', 'RuleTitle', 'Channel')):
        return None
    ev = EvidenceEvent(
        timestamp=_get(row, 'Timestamp', 'TimeCreated', 'TimeGenerated', 'datetime'),
        computer=_get(row, 'Computer', 'ComputerName', 'Hostname') or 'DESCONOCIDO',
        event_id=_get(row, 'EventID', 'Event ID', 'Id'),
        channel=_get(row, 'Channel', 'LogName'),
        title=_get(row, 'RuleTitle', 'Title'),
        details=' | '.join(filter(None, (_get(row, 'Details', 'Message'),
                         _get(row, 'ExtraFieldInfo'), _get(row, 'AllFieldInfo')))),
        level=_get(row, 'Level', 'Severity'),
        source=source,
        record_id=_get(row, 'RecordID', 'EventRecordID'),
        rule_id=_get(row, 'RuleID'),
        raw=row,
    )
    return ev


def hash_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for part in iter(lambda: f.read(1024 * 1024), b''):
            h.update(part)
    return h.hexdigest()


def iter_jsonl(stream):
    with io.TextIOWrapper(stream, encoding='utf-8-sig', errors='replace') as text_stream:
        for number, line in enumerate(text_stream, 1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f'JSONL no válido, línea {number}: {exc}') from exc


def iter_csv(stream):
    with io.TextIOWrapper(stream, encoding='utf-8-sig', errors='replace', newline='') as text_stream:
        yield from csv.DictReader(text_stream)


def iter_json(stream):
    with io.TextIOWrapper(stream, encoding='utf-8-sig', errors='replace') as text_stream:
        data = json.load(text_stream)
    if isinstance(data, list):
        yield from data
    elif isinstance(data, dict) and isinstance(data.get('events'), list):
        yield from data['events']
    else:
        yield data


def load_sources(inputs, max_events=200_000, hayabusa=None):
    events, snapshots, manifest, warnings = [], [], [], []
    count = 0

    def consume(file_obj, source, suffix):
        nonlocal count
        try:
            iterator = (iter_jsonl(file_obj) if suffix in {'.jsonl', '.ndjson'}
                        else iter_csv(file_obj) if suffix == '.csv'
                        else iter_json(file_obj))
            for row in iterator:
                if isinstance(row, dict) and ('security_snapshot' in row or 'SecuritySnapshot' in row):
                    snapshots.append((row.get('security_snapshot') or row.get('SecuritySnapshot'), source))
                    continue
                event = normalize(row, source)
                if event:
                    events.append(event)
                    count += 1
                    if count > max_events:
                        raise ValueError(f'Se excedió --max-events ({max_events}); análisis abortado, no truncado.')
                else:
                    warnings.append(f'Registro sin formato de evento omitido: {source}')
        except (UnicodeError, ValueError, csv.Error, json.JSONDecodeError) as exc:
            raise ValueError(f'Error en {source}: {exc}') from exc

    for item in inputs:
        p = Path(item).resolve()
        if not p.exists():
            raise FileNotFoundError(p)
        paths = sorted(f for f in p.rglob('*') if f.is_file()) if p.is_dir() else [p]
        for file in paths:
            suffix = file.suffix.lower()
            if suffix == '.zip':
                manifest.append({'path': str(file), 'sha256': hash_file(file), 'size': file.stat().st_size, 'type': 'archive'})
                with zipfile.ZipFile(file) as z:
                    for member in z.infolist():
                        if member.is_dir():
                            continue
                        filename = Path(member.filename)
                        kind = filename.suffix.lower()
                        label = f'{file.name}!/{member.filename}'
                        if member.file_size > MAX_ENTRY_BYTES:
                            warnings.append(f'Archivo del ZIP omitido (>250 MB): {label}')
                            continue
                        if kind in SUPPORTED and filename.name.lower() not in {'sha256_files.json'}:
                            with z.open(member) as stream:
                                # Snapshot JSON and event files are distinguished by content.
                                consume(stream, label, kind)
                        elif kind == '.evtx':
                            warnings.append(f'EVTX sin procesar dentro de ZIP: {label}. Utiliza --hayabusa o exporta con Hayabusa.')
                continue
            manifest.append({'path': str(file), 'sha256': hash_file(file), 'size': file.stat().st_size,
                             'type': 'input'})
            if suffix in SUPPORTED and file.name.lower() not in {'sha256_files.json'}:
                if file.stat().st_size > MAX_ENTRY_BYTES:
                    warnings.append(f'Archivo omitido (>250 MB): {file}')
                    continue
                with file.open('rb') as stream:
                    consume(stream, str(file), suffix)
            elif suffix == '.evtx':
                warnings.append(f'EVTX sin procesar: {file}. Utiliza --hayabusa para analizarlo.')
    if hayabusa:
        # Option explicitly requests binary execution against raw EVTX; avoids arbitrary shell use.
        with tempfile.TemporaryDirectory(prefix='dfir-evtx-') as tmp:
            evtx_dir = Path(tmp) / 'evtx'
            evtx_dir.mkdir()
            out = Path(tmp) / 'hayabusa.jsonl'
            count_evtx = 0
            for input_item in inputs:
                input_path = Path(input_item).resolve()
                candidates = sorted(f for f in input_path.rglob('*') if f.is_file()) if input_path.is_dir() else [input_path]
                for candidate in candidates:
                    if candidate.suffix.lower() == '.evtx':
                        dest = evtx_dir / f'{count_evtx:06}_{candidate.name}'
                        shutil.copyfile(candidate, dest)
                        count_evtx += 1
                    elif candidate.suffix.lower() == '.zip':
                        with zipfile.ZipFile(candidate) as z:
                            for member in z.infolist():
                                if (not member.is_dir() and Path(member.filename).suffix.lower() == '.evtx'):
                                    if member.file_size > MAX_ENTRY_BYTES:
                                        continue
                                    dest = evtx_dir / f'{count_evtx:06}_{Path(member.filename).name}'
                                    with z.open(member) as src, dest.open('wb') as dst:
                                        for chunk in iter(lambda: src.read(1024 * 1024), b''):
                                            dst.write(chunk)
                                    count_evtx += 1
            if count_evtx:
                cmd = [hayabusa, 'dfir-timeline', '-d', str(evtx_dir), '-t', 'jsonl',
                       '-p', 'super-verbose', '-U', '-w', '-o', str(out), '-q']
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, check=False)
                except (OSError, subprocess.TimeoutExpired) as exc:
                    raise RuntimeError(f'Hayabusa no pudo ejecutarse: {exc}') from exc
                if result.returncode != 0 or not out.is_file():
                    raise RuntimeError(f'Hayabusa devolvió {result.returncode}: {result.stderr[-1600:]}')
                with out.open('rb') as f:
                    consume(f, f'Hayabusa (generado desde {count_evtx} EVTX)', '.jsonl')
                warnings = [w for w in warnings if not w.startswith(('EVTX sin procesar', 'EVTX sin procesar dentro'))]
            else:
                warnings.append('Se indicó --hayabusa, pero no se encontraron archivos EVTX.')

    if not events and not snapshots:
        warnings.append('No se cargaron eventos ni snapshots compatibles.')
    return events, snapshots, manifest, sorted(set(warnings))
