import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkPins } from './check-pins.mjs';
const source = 'git+https://github.com/corbet-foss/crlt?branch=main#' + 'a'.repeat(40);
const pkg = { name: 'crlt', source };
test('accept main with one exact lock revision', () => checkPins({ packages: [pkg] }));
test('reject duplicate versions and pinned or unqualified sources', () => {
  assert.throws(() => checkPins({ packages: [pkg, pkg] }));
  for (const bad of [source.replace('branch=main', 'rev=abc'), source.replace('main', 'next'), source.slice(0, -1)]) {
    assert.throws(() => checkPins({ packages: [{ name: 'crlt', source: bad }] }));
  }
});
test('reject pinned transitive declarations', () => {
  assert.throws(() => checkPins({ packages: [{ ...pkg, dependencies: [{ source: source.replace('branch=main', 'rev=abc') }] }] }));
});
