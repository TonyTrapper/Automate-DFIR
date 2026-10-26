#!/usr/bin/env python3
"""DFIR AI MVP: análisis local y reproducible de exportaciones forenses Windows."""
import argparse
import sys
from pathlib import Path
from dfir_ia import __version__
from dfir_ia.ingest import load_sources
from dfir_ia.detect import detect
from dfir_ia.report import report
from dfir_ia.ai import review


def main(argv=None):
    p = argparse.ArgumentParser(description='Automatización DFIR con reglas y revisión IA opcional en Ollama local.')
    p.add_argument('--version', action='version', version=f'DFIR AI {__version__}')
    p.add_argument('--input', '-i', nargs='+', required=True, help='CSV/JSON(L) Hayabusa, snapshot JSON, ZIP o carpeta de archivos.')
    p.add_argument('--out', '-o', default='salida', help='Carpeta de resultados.')
    p.add_argument('--hayabusa', metavar='EJECUTABLE', help='Procesa .evtx con Hayabusa (ej.: --hayabusa hayabusa).')
    p.add_argument('--ai', action='store_true', help='Habilita revisión opcional por Ollama local.')
    p.add_argument('--model', default='qwen2.5:7b', help='Modelo de Ollama previamente descargado.')
    p.add_argument('--ai-url', default='http://127.0.0.1:11434', help='Solo HTTP local por loopback.')
    p.add_argument('--max-events', type=int, default=200000, help='Límite que provoca error si se supera; no trunca.')
    p.add_argument('--no-docx', action='store_true', help='No producir Word.')
    args = p.parse_args(argv)
    if args.max_events < 1:
        p.error('--max-events debe ser mayor que cero')
    try:
        events, snapshots, manifest, warnings = load_sources(args.input, args.max_events, args.hayabusa)
        findings = detect(events, snapshots)
        ai_result = None
        if args.ai:
            if not findings:
                warnings.append('No se consultó IA: no hay hallazgos para evaluar.')
            else:
                ai_result = review(findings, args.model, args.ai_url)
        data = report(args.out, findings, events, manifest, warnings, ai_result, not args.no_docx)
    except Exception as exc:
        print(f'[ERROR] {exc}', file=sys.stderr)
        return 1
    print(f"[OK] Eventos: {len(events)} | Snapshots: {len(snapshots)} | Hallazgos: {len(findings)} | Hosts: {len(data['hosts'])}")
    print('[OK] Salida:', Path(args.out).resolve())
    if warnings:
        print(f'[AVISO] {len(warnings)} advertencias. Consulte hallazgos.json.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
