#!/usr/bin/env python3
"""Exclusions remain source-pinned, line-only and visible in complete reports."""
import copy
import importlib.util
import json
import tempfile
from pathlib import Path

spec = importlib.util.spec_from_file_location('gate', Path(__file__).with_name('check-source-coverage.py'))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    (root / 'src').mkdir()
    (root / 'docs').mkdir()
    source = root / 'src/lib.rs'
    source.write_text('first\ndefensive mapping\nthird\n')
    item = {'path': 'src/lib.rs', 'line': 2, 'context': source.read_text().splitlines(), 'reason': 'Concrete infallible serialization'}
    exclusion = root / 'docs/coverage-exclusions.json'
    lcov = f'SF:{source}\nDA:1,1\nDA:2,0\nLF:2\nLH:1\nBRF:0\nBRH:0\nend_of_record\n'
    raw = {'type': 'llvm.coverage.json.export', 'data': [{'files': [{'filename': str(source), 'branches': [], 'summary': {'lines': {'count': 2, 'covered': 1}, 'branches': {'count': 0, 'covered': 0}}}]}]}
    annotated = f'{source}:\n1| 1| first\n2| 0| defensive mapping\n'
    for case in range(9):
        entries = [copy.deepcopy(item)]
        text, report, shown = lcov, copy.deepcopy(raw), annotated
        if case == 1:
            entries[0]['context'][1] = 'changed source'
        elif case == 2:
            entries[0]['reason'] = ''
        elif case == 3:
            entries *= 2
        elif case == 4:
            entries[0]['line'] = 3
        elif case == 5:
            text = text.replace('DA:2,0', 'DA:2,1').replace('LH:1', 'LH:2')
            report['data'][0]['files'][0]['summary']['lines']['covered'] = 2
            shown = shown.replace('2| 0|', '2| 1|')
        elif case == 6:
            text = text.replace('BRF:0\nBRH:0', 'BRDA:2,0,0,1\nBRDA:2,0,1,1\nBRF:2\nBRH:2')
            report['data'][0]['files'][0]['branches'] = [[2, 1, 2, 2]]
            report['data'][0]['files'][0]['summary']['branches'] = {'count': 2, 'covered': 2}
        elif case == 7:
            text = text.replace('DA:2,0\n', '')
        elif case == 8:
            entries = []
        exclusion.write_text(json.dumps(entries))
        try:
            gate.check(text, report, root, shown)
            passed = True
        except ValueError:
            passed = False
        assert passed == (case == 0), f'case {case}'
print('Coverage exclusion integrity: 9 cases passed')
