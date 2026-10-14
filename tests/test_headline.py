import csv
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('headline', ROOT/'eval/reproduce_cscloud_headline.py')
headline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(headline)


class HeadlineTests(unittest.TestCase):
    def test_manifest_and_expected_metrics(self):
        folder = headline.DEFAULT_CSV.parent
        manifest = json.loads((folder/'manifest.json').read_text(encoding='utf-8'))
        self.assertEqual(hashlib.sha256(headline.DEFAULT_CSV.read_bytes()).hexdigest(),
                         manifest['export_sha256'])
        self.assertEqual(manifest['source_database_sha256'], headline.SOURCE_SHA256)
        expected = json.loads((folder/'metrics.json').read_text(encoding='utf-8'))
        self.assertEqual(headline.summarize(headline.load_predictions(headline.DEFAULT_CSV)), expected)

    def test_archived_counts_and_trial_coverage(self):
        rows = headline.load_predictions(headline.DEFAULT_CSV)
        result = headline.summarize(rows)
        self.assertEqual([result[k] for k in ['tp','fp','tn','fn']], [667,372,378,83])
        self.assertEqual(result['functions'], 300)
        self.assertEqual(result['trials'], 5)
        self.assertAlmostEqual(result['accuracy'], 1045/1500)
        self.assertAlmostEqual(result['recall'], 667/750)
        self.assertAlmostEqual(result['specificity'], 378/750)
        for t in result['per_trial']:
            self.assertEqual(t['records'], 300)
            self.assertEqual(t['tp']+t['fn'], 150)

    def test_duplicate_keys_rejected(self):
        with headline.DEFAULT_CSV.open(newline='', encoding='utf-8') as stream:
            reader = csv.DictReader(stream)
            row = next(reader)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'duplicate.csv'
            with path.open('w', newline='', encoding='utf-8') as stream:
                writer = csv.DictWriter(stream, fieldnames=headline.FIELDS)
                writer.writeheader()
                writer.writerows([row,row])
            with self.assertRaisesRegex(ValueError, 'Duplicate'):
                headline.load_predictions(path)

    def test_invalid_label_rejected(self):
        with self.assertRaises(ValueError):
            headline.parse_bool('unknown')


if __name__ == '__main__':
    unittest.main()
