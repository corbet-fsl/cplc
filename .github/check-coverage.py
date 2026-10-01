#!/usr/bin/env python3
"""Fail closed unless production line and branch coverage are both complete."""
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text())
if report.get('type') != 'llvm.coverage.json.export' or not report.get('data'):
    raise SystemExit('Missing LLVM coverage data')
failed = False
for data in report['data']:
    for metric in ('lines', 'branches'):
        total = data['totals'][metric]
        count, covered = total['count'], total['covered']
        print(f'{metric}: {covered}/{count}')
        if count <= 0 or covered != count:
            failed = True
if failed:
    raise SystemExit('Require 100% measured production line and branch coverage')
