#!/usr/bin/env python3
"""Muninn CLI: test runner, module inspector, and conservative audit coordinator.

Auditors are not assumed to share an API. Audit runs are staged until an
explicitly implemented adapter exists; no network requests are made here.
"""
from __future__ import annotations

import argparse
import ast
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import uuid
from typing import Any

VERSION = '0.3.0'
ROOT = Path(__file__).resolve().parent
AUDIT_DIR = ROOT / 'audit'
TEST_DIR = ROOT / 'tests'
OUTPUT_DIR = ROOT / 'output'
NAME_RE = re.compile(r'^[a-z][a-z0-9_]{0,79}$')
RUN_RE = re.compile(r'^[a-zA-Z0-9_-]{1,100}$')

class MuninnError(Exception):
    pass

def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')

def atomic_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(prefix='.muninn-', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def inventory(directory: Path, *, prefix: str = '') -> list[dict[str, Any]]:
    if not directory.is_dir():
        return []
    entries = []
    for path in sorted(directory.glob('*.py')):
        if path.name == '__init__.py' or path.is_symlink():
            continue
        name = path.stem
        if prefix and not name.startswith(prefix):
            continue
        if not NAME_RE.fullmatch(name):
            continue
        item: dict[str, Any] = {'name': name, 'file': str(path.relative_to(ROOT)), 'syntax': 'ok', 'classes': []}
        try:
            tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
            item['classes'] = [node.name for node in tree.body if isinstance(node, ast.ClassDef)]
        except (OSError, UnicodeError, SyntaxError) as exc:
            item['syntax'] = f'{type(exc).__name__}: {str(exc)[:160]}'
        entries.append(item)
    return entries

def audit_inventory() -> list[dict[str, Any]]:
    return inventory(AUDIT_DIR)

def test_inventory() -> list[dict[str, Any]]:
    return inventory(TEST_DIR, prefix='test_')

def doctor() -> dict[str, Any]:
    deps = ('defusedxml', 'packaging', 'yaml')
    audits = audit_inventory()
    return {
        'version': VERSION, 'python': sys.version.split()[0], 'root': str(ROOT),
        'directories': {name: (ROOT / name).is_dir() for name in ('core', 'integrations', 'audit', 'tests')},
        'dependencies': {name: importlib.util.find_spec(name) is not None for name in deps},
        'auditor_files': len(audits), 'test_files': len(test_inventory()),
        'auditor_syntax_errors': [a['name'] for a in audits if a['syntax'] != 'ok'],
        'audit_execution': 'not integrated: no auditor adapter APIs have been verified',
    }

def safe_file(path: Path, *, max_bytes: int, description: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise MuninnError(f'{description} missing, not a regular file, or symlinked')
    if path.stat().st_size > max_bytes:
        raise MuninnError(f'{description} exceeds {max_bytes} bytes')
    return path

def read_scope(path: Path) -> dict[str, Any]:
    safe_file(path, max_bytes=1024 * 1024, description='Scope file')
    try:
        import yaml
    except ImportError as exc:
        raise MuninnError('PyYAML is required: python -m pip install pyyaml') from exc
    try:
        result = yaml.safe_load(path.read_text(encoding='utf-8'))
    except (yaml.YAMLError, UnicodeError) as exc:
        raise MuninnError('Invalid scope YAML') from exc
    if not isinstance(result, dict) or not result:
        raise MuninnError('Scope must be a nonempty YAML mapping')
    return result

def selected_names(request: str | None, available: list[dict[str, Any]], *, test: bool = False) -> list[str]:
    lookup = {x['name']: x for x in available}
    if request is None or request == 'all':
        names = sorted(lookup)
    else:
        names = [s.strip() for s in request.split(',')]
        if test:
            names = [s if s.startswith('test_') else f'test_{s}' for s in names]
    if not names or len(names) != len(set(names)) or any(not NAME_RE.fullmatch(n) for n in names):
        raise MuninnError('Empty, duplicate, or invalid selection')
    unknown = sorted(set(names) - lookup.keys())
    if unknown:
        raise MuninnError('Unknown modules: ' + ', '.join(unknown))
    broken = [n for n in names if lookup[n]['syntax'] != 'ok']
    if broken:
        raise MuninnError('Syntax errors in: ' + ', '.join(broken))
    return names

def run_tests(selection: str | None, *, verbose: bool = False, timeout: int = 180) -> int:
    if not 1 <= timeout <= 3600:
        raise MuninnError('Test timeout must be between 1 and 3600 seconds')
    names = selected_names(selection, test_inventory(), test=True)
    # unittest discovery imports all selected modules; do not execute arbitrary filenames.
    cmd = [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_*.py', '-v' if verbose else '-q']
    if selection not in (None, 'all'):
        cmd = [sys.executable, '-m', 'unittest', *[f'tests.{n}' for n in names]]
        if verbose:
            cmd.append('-v')
    print('Muninn test runner:', ', '.join(names) if selection not in (None, 'all') else 'all tests', flush=True)
    try:
        result = subprocess.run(cmd, cwd=ROOT, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        print(f'Tests exceeded {timeout}s timeout', file=sys.stderr)
        return 124
    return result.returncode

def create_run(scope_path: Path, selected: list[str], source: Path | None, dry_run: bool) -> dict[str, Any]:
    read_scope(scope_path)  # Syntax validation is NOT authorization verification.
    available = {a['name']: a for a in audit_inventory()}
    if not selected or any(n not in available or available[n]['syntax'] != 'ok' for n in selected):
        raise MuninnError('Unknown or syntactically invalid auditor')
    if source is not None:
        safe_file(source, max_bytes=100 * 1024 * 1024, description='Capture file')
    run_id = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:10]
    result = {
        'schema_version': 1, 'version': VERSION, 'run_id': run_id,
        'created_at': utc_now(), 'mode': 'passive',
        'status': 'planned' if dry_run else 'awaiting_adapters',
        'scope_sha256': hashlib.sha256(scope_path.read_bytes()).hexdigest(),
        'capture': {'present': source is not None, 'size_bytes': source.stat().st_size if source else 0},
        'auditors': [{'name': n, 'status': 'not_executed', 'reason': 'adapter_not_integrated'} for n in selected],
        'findings': [],
        'warnings': ['No auditor analysis or HTTP activity was performed.', 'YAML syntax validation does not verify scope authorization.'],
    }
    if not dry_run:
        run_dir = OUTPUT_DIR / 'runs' / run_id
        run_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
        atomic_json(run_dir / 'manifest.json', result)
    return result

def read_report(run_id: str) -> dict[str, Any]:
    if not RUN_RE.fullmatch(run_id):
        raise MuninnError('Invalid run ID')
    path = OUTPUT_DIR / 'runs' / run_id / 'manifest.json'
    safe_file(path, max_bytes=10 * 1024 * 1024, description='Run manifest')
    result = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(result, dict):
        raise MuninnError('Invalid run manifest')
    return result

def parser_factory() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Muninn security framework: inspect, test, and stage passive audits')
    parser.add_argument('--version', action='version', version=f'Muninn {VERSION}')
    commands = parser.add_subparsers(dest='command')
    commands.add_parser('doctor', help='Check installation and dependencies')
    commands.add_parser('list-auditors', help='List discovered auditor files')
    commands.add_parser('list-tests', help='List discovered test modules')
    tests = commands.add_parser('test', help='Run all or selected unittest modules')
    tests.add_argument('--modules', help='Comma-separated test names, e.g. ssrf,xss; default all')
    tests.add_argument('--verbose', '-v', action='store_true')
    tests.add_argument('--timeout', type=int, default=180)
    module = commands.add_parser('module', help='Inspect one auditor without executing it')
    module.add_argument('name')
    audit = commands.add_parser('audit', help='Run offline passive analysis of Burp XML')
    audit.add_argument('--scope', type=Path, default=ROOT / 'scope.yaml')
    audit.add_argument('--burp', type=Path)
    audit.add_argument('--auditors', help='Comma-separated names; default all')
    audit.add_argument('--mode', choices=['passive'], default='passive')
    audit.add_argument('--dry-run', action='store_true')
    audit.add_argument('--execute', action='store_true', help='Actually analyze Burp XML offline; no HTTP requests')
    report = commands.add_parser('report', help='Read a staged audit manifest')
    report.add_argument('--run-id', required=True)
    return parser

def interactive(parser: argparse.ArgumentParser) -> list[str]:
    if not sys.stdin.isatty():
        parser.print_help()
        return []
    print('\nMUNINN  |  Security Audit Framework\n')
    print('1. Run all tests\n2. Run selected tests\n3. List auditors\n4. System doctor\n5. Stage passive audit\n6. Exit')
    try:
        choice = input('\nSelect [1-6]: ').strip()
        if choice == '1': return ['test', '--verbose']
        if choice == '2':
            names = input('Test modules (e.g. ssrf,xss): ').strip()
            return ['test', '--modules', names, '--verbose']
        if choice == '3': return ['list-auditors']
        if choice == '4': return ['doctor']
        if choice == '5': return ['audit']
    except (EOFError, KeyboardInterrupt):
        print()
    return []

def main(argv: list[str] | None = None) -> int:
    parser = parser_factory()
    args_list = list(sys.argv[1:] if argv is None else argv)
    if not args_list:
        args_list = interactive(parser)
        if not args_list:
            return 0
    args = parser.parse_args(args_list)
    try:
        if args.command == 'test':
            return run_tests(args.modules, verbose=args.verbose, timeout=args.timeout)
        if args.command == 'doctor': result = doctor()
        elif args.command == 'list-auditors': result = {'auditors': audit_inventory()}
        elif args.command == 'list-tests': result = {'tests': test_inventory()}
        elif args.command == 'module':
            matches = [a for a in audit_inventory() if a['name'] == args.name]
            if not matches: raise MuninnError('Unknown auditor: ' + args.name)
            result = {'auditor': matches[0], 'execution': 'not integrated', 'note': 'Use test --modules NAME to run its unit tests.'}
        elif args.command == 'audit':
            names = selected_names(args.auditors, audit_inventory())
            if args.execute:
                if args.dry_run or args.burp is None:
                    raise MuninnError('--execute requires --burp and cannot be combined with --dry-run')
                from passive_engine import analyze_burp, PassiveError
                scope = read_scope(args.scope)
                safe_file(args.burp, max_bytes=100 * 1024 * 1024, description='Capture file')
                result = create_run(args.scope, names, args.burp, True)
                try:
                    analysis = analyze_burp(args.burp, scope, names)
                except PassiveError as exc:
                    raise MuninnError(str(exc)) from exc
                result['status'] = 'completed_passive_analysis'
                result['stats'] = analysis['stats']
                result['findings'] = analysis['findings']
                result['finding_limit_reached'] = analysis['finding_limit_reached']
                supported = {'cors', 'xss', 'sensitive_data_exposure'}
                result['auditors'] = [{'name': n, 'status': 'passive_heuristics_only' if n in supported else 'not_executed',
                    'reason': 'existing auditor API not yet integrated' if n not in supported else 'limited offline signals only'} for n in names]
                result['warnings'] = ['Offline passive heuristics only; no active probes or exploitation.',
                    'No existing audit/*.py auditor was invoked.', 'Findings are unverified indicators, not confirmed vulnerabilities.']
                run_dir = OUTPUT_DIR / 'runs' / result['run_id']
                run_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
                atomic_json(run_dir / 'manifest.json', result)
            else:
                result = create_run(args.scope, names, args.burp, args.dry_run)
        elif args.command == 'report': result = read_report(args.run_id)
        else:
            parser.print_help()
            return 0
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (MuninnError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f'Muninn error: {exc}', file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
