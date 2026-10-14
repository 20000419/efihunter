"""Offline context-construction checks on synthetic graphs; no model calls."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('dcc', ROOT / 'analyze/analyze_dcc.py')
dcc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dcc)


class ContextTests(unittest.TestCase):
    def run_graph(self, relations, flags, root='A'):
        with patch.object(dcc, 'read_source', side_effect=lambda _, n: 'void '+n+'(void) {}'):
            return dcc.long_term_memory(root, relations, 'unused', dict.fromkeys(flags, True),
                                       {n: {'name': n} for n in flags})

    def test_mutual_cycle(self):
        _, paths = self.run_graph({'A':['B'], 'B':['C'], 'C':['B']}, ['B','C'])
        self.assertEqual(paths, ['A -> B', 'A -> B -> C'])

    def test_self_loop(self):
        _, paths = self.run_graph({'A':['B'], 'B':['B']}, ['B'])
        self.assertEqual(paths, ['A -> B'])

    def test_root_not_reintroduced(self):
        _, paths = self.run_graph({'A':['B'], 'B':['A']}, ['A','B'])
        self.assertEqual(paths, ['A -> B'])

    def test_clean_branch_stops(self):
        _, paths = self.run_graph({'A':['B','C'], 'B':['D'], 'C':['E']}, ['B','D','E'])
        self.assertEqual(paths, ['A -> B', 'A -> B -> D'])

    def test_shared_descendant(self):
        text, paths = self.run_graph({'A':['B','C'], 'B':['D'], 'C':['D']}, ['B','C','D'])
        self.assertEqual(text.count('// flagged callee: D'), 1)
        self.assertEqual(paths, ['A -> B', 'A -> B -> D', 'A -> C'])

    def test_empty(self):
        self.assertEqual(self.run_graph({'A':['B']}, []), ('', []))

    def test_deep_chain(self):
        graph = {str(i): [str(i+1)] for i in range(1200)}
        _, paths = self.run_graph(graph, [str(i) for i in range(1,1201)], root='0')
        self.assertEqual(len(paths), 1200)

    def test_short_term_keeps_clean_callees(self):
        with patch.object(dcc, 'read_source', side_effect=lambda _, n: 'void '+n+'(void) {}'):
            text = dcc.short_term_memory('A', {'A':['B','C']}, 'unused')
        self.assertIn('void B', text)
        self.assertIn('void C', text)

    def test_batch_reads_previous_snapshot(self):
        # Mutual callees in batch 1 must not see one another's new findings.
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp) / 'module'
            folder.mkdir()
            for n in ['A','B','C']:
                (folder / (n+'.c')).write_text('void '+n+'(void) {}')
            (folder/'function_batches.txt').write_text('Batch 1: A, B\nBatch 2: C\n')
            (folder/'function_call_relations.txt').write_text('A: B\nB: A\nC: A, B\n')
            prompts = []
            def infer(prompt, model):
                prompts.append(prompt)
                return '', json.dumps({'risk_level': 'high'})
            with patch.object(dcc, 'analyse', side_effect=infer):
                count = dcc.process_module(str(folder), 'rubric', 'mock', str(Path(temp)/'out'))
            self.assertEqual(count, 3)
            self.assertNotIn('### Findings on flagged call chains', prompts[0])
            self.assertNotIn('### Findings on flagged call chains', prompts[1])
            self.assertIn('### Findings on flagged call chains', prompts[2])


if __name__ == '__main__':
    unittest.main()
