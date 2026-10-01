import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
const firstParty = /^git\+https:\/\/github\.com\/corbet-(?:foss|libs)\//;
export function checkPins(metadata) {
  const names = new Set();
  const check = (source, resolved) => {
    if (!firstParty.test(source ?? '')) return;
    const url = new URL(source.slice(4));
    if (url.search !== '?branch=main' || (resolved && !/^#[a-f0-9]{40}$/.test(url.hash))) {
      throw new Error('Expected main and an exact locked revision');
    }
  };
  for (const pkg of metadata.packages) {
    if (firstParty.test(pkg.source ?? '')) { names.add(pkg.name); check(pkg.source, true); }
    for (const dep of pkg.dependencies ?? []) check(dep.source, false);
  }
  for (const name of names) {
    if (metadata.packages.filter(pkg => pkg.name === name).length !== 1) throw new Error('Duplicated first-party dependency');
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  checkPins(JSON.parse(readFileSync(process.argv[2], 'utf8')));
}
