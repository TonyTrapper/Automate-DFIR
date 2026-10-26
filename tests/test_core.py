import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from dfir_ia.ingest import load_sources
from dfir_ia.detect import detect
from dfir_ia.ai import redact, review

ROOT = Path(__file__).resolve().parents[1]

class PipelineTest(unittest.TestCase):
    def test_sample_pipeline(self):
        events, snaps, manifest, warnings = load_sources(
            [ROOT/'samples/hayabusa_demo.jsonl', ROOT/'samples/security_snapshot.json'])
        self.assertEqual(len(events), 10)
        self.assertEqual(len(snaps), 1)
        self.assertEqual(len(manifest), 2)
        results = detect(events, snaps)
        names = [f['title'] for f in results]
        self.assertIn('Proximidad temporal: PowerShell y cambio de Defender', names)
        self.assertIn('Múltiples autenticaciones fallidas desde una IP', names)
        self.assertIn('AutoAdminLogon habilitado', names)
        self.assertTrue(all(f['evidence'] for f in results))
        self.assertTrue(all(f['status'] == 'Pendiente de validación humana' for f in results))

    def test_zip_input(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'evidencia.zip'
            with zipfile.ZipFile(p, 'w') as z:
                z.write(ROOT/'samples/hayabusa_demo.jsonl', 'logs/timeline.jsonl')
                z.write(ROOT/'samples/security_snapshot.json', 'security_snapshot.json')
            events, snaps, manifest, warnings = load_sources([p])
            self.assertEqual(len(events), 10)
            self.assertEqual(len(snaps), 1)
            self.assertEqual(len(manifest), 1)

    def test_event_cap_is_error(self):
        with self.assertRaisesRegex(ValueError, 'max-events'):
            load_sources([ROOT/'samples/hayabusa_demo.jsonl'], max_events=3)

    def test_redacts_secrets(self):
        txt = redact('password=hello123 apiKey=abcxyz Bearer eyJ123abcdef test@lab.org')
        self.assertNotIn('hello123', txt)
        self.assertNotIn('test@lab.org', txt)

    def test_ia_rejects_public_endpoint(self):
        with self.assertRaisesRegex(ValueError, 'loopback'):
            review([], 'model', 'https://example.org')

if __name__ == '__main__':
    unittest.main()
