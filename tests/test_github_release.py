"""Pruebas de integración sin binario Hayabusa real ni servicios externos."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from dfir_ia.ingest import load_sources
from dfir_ia.report import report

ROOT = Path(__file__).resolve().parents[1]


class GitHubReleaseTest(unittest.TestCase):
    def test_cli_without_docx(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / 'out'
            run = subprocess.run([
                sys.executable, 'main.py', '-i',
                'samples/hayabusa_demo.jsonl', 'samples/security_snapshot.json',
                '-o', str(out), '--no-docx',
            ], cwd=ROOT, text=True, capture_output=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            data = json.loads((out / 'hallazgos.json').read_text(encoding='utf-8'))
            self.assertEqual(data['event_count'], 10)
            self.assertTrue(data['findings'])
            self.assertTrue((out / 'informe.html').exists())
            self.assertFalse((out / 'informe.docx').exists())

    def test_version(self):
        run = subprocess.run([sys.executable, 'main.py', '--version'], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(run.returncode, 0)
        self.assertIn('0.1.1', run.stdout)

    def test_unattended_hayabusa_from_zip(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            sample = ROOT / 'samples/hayabusa_demo.jsonl'
            with zipfile.ZipFile(folder / 'evidence.zip', 'w') as z:
                z.writestr('windows/security.evtx', b'fake-eventlog')
            # Fake Hayabusa executable reproduces the external tool output.
            fake = folder / 'fake_hayabusa.py'
            fake.write_text(
                '#!' + sys.executable + '\n' +
                'import pathlib,sys\n' +
                'assert "-w" in sys.argv\n' +
                'pathlib.Path(sys.argv[sys.argv.index("-o")+1]).write_bytes(' + repr(sample.read_bytes()) + ')\n',
                encoding='utf-8',
            )
            fake.chmod(0o700)
            events, snapshots, manifest, warnings = load_sources([folder / 'evidence.zip'], hayabusa=str(fake))
            self.assertEqual(len(events), 10)
            self.assertEqual(len(manifest), 1)
            self.assertFalse(any('EVTX sin procesar' in w for w in warnings))

    def test_report_no_docx(self):
        with tempfile.TemporaryDirectory() as folder:
            data = report(folder, [], [], [], [], docx=False)
            self.assertEqual(data['event_count'], 0)
            self.assertFalse((Path(folder) / 'informe.docx').exists())

if __name__ == '__main__':
    unittest.main()
