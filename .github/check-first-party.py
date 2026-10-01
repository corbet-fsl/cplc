#!/usr/bin/env python3
"""Require main declarations and one exact locked revision per first-party crate."""
import json
import re
import sys
import tomllib
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

FIRST_PARTY = re.compile(r"^(?:git\+)?https://github\.com/corbet-(?:foss|libs)/")
SHA = re.compile(r"^[0-9a-f]{40}$")


def check_source(source, resolved):
    parsed = urlsplit(source.removeprefix('git+'))
    if parse_qs(parsed.query) != {'branch': ['main']}:
        raise ValueError('First-party dependencies must follow main')
    if resolved and not SHA.fullmatch(parsed.fragment):
        raise ValueError('Locked first-party revisions must be full hashes')


def check_packages(packages):
    names = {p['name'] for p in packages if FIRST_PARTY.match(p.get('source') or '')}
    for name in names:
        entries = [p for p in packages if p['name'] == name]
        if len(entries) != 1:
            raise ValueError(f'Duplicate first-party crate: {name}')
        check_source(entries[0]['source'], True)
    for package in packages:
        for dependency in package.get('dependencies', []):
            if isinstance(dependency, dict) and FIRST_PARTY.match(dependency.get('source') or ''):
                check_source(dependency['source'], False)


def check_manifest(value):
    if isinstance(value, dict):
        if FIRST_PARTY.match(value.get('git', '')):
            if value.get('branch') != 'main' or 'rev' in value or 'tag' in value:
                raise ValueError('First-party declarations must use branch main')
        for item in value.values():
            check_manifest(item)
    elif isinstance(value, list):
        for item in value:
            check_manifest(item)


def self_test():
    source = 'git+https://github.com/corbet-foss/example?branch=main#' + 'a' * 40
    package = {'name': 'example', 'source': source}
    check_packages([package])
    check_manifest({'git': 'https://github.com/corbet-foss/example', 'branch': 'main'})
    for packages in [[package, package], [package, {'name': 'example'}],
                     [{'name': 'example', 'source': source.replace('main', 'next')}],
                     [{'name': 'example', 'source': source.replace('branch=main', 'rev=abc')}],
                     [{'name': 'example', 'source': source[:-1]}],
                     [dict(package, dependencies=[{'source': source.replace('branch=main', 'rev=abc')}])]]:
        try:
            check_packages(packages)
        except ValueError:
            continue
        raise AssertionError('Invalid dependency graph accepted')
    for value in [{'git': 'https://github.com/corbet-foss/example', 'rev': 'a' * 40},
                  {'git': 'https://github.com/corbet-foss/example', 'branch': 'main', 'tag': 'v1'}]:
        try:
            check_manifest(value)
        except ValueError:
            continue
        raise AssertionError('Invalid manifest accepted')


if __name__ == '__main__':
    self_test()
    if '--self-test' not in sys.argv:
        check_packages(tomllib.loads(Path('Cargo.lock').read_text())['package'])
        metadata = Path('dependency-metadata.json')
        if metadata.exists():
            check_packages(json.loads(metadata.read_text())['packages'])
        for manifest in Path('.').rglob('Cargo.toml'):
            if not {'.git', '.build', 'target', 'node_modules'}.intersection(manifest.parts):
                check_manifest(tomllib.loads(manifest.read_text()))
        print('First-party dependencies follow main with one locked revision per crate')
