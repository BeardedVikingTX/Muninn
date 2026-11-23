import json
import unittest
from audit.dependency_vulnerabilities import (
    Dependency, DependencyVulnerabilityAuditor, InventoryError,
    parse_requirements, parse_package_lock, parse_cyclonedx,
    _compare, _affected,
)


def advisory(eco='PyPI', name='demo', events=None, versions=None, aid='OSV-TEST-1'):
    return {'id': aid, 'aliases': ['CVE-2099-0001'], 'affected': [{
        'package': {'ecosystem': eco, 'name': name},
        'ranges': [{'type': 'ECOSYSTEM', 'events': events}] if events else [],
        'versions': versions or [],
    }]}


class VersionTests(unittest.TestCase):
    def test_pep440(self):
        self.assertLess(_compare('PyPI', '1.0rc1', '1.0'), 0)
    def test_pypi_normalization(self):
        report = DependencyVulnerabilityAuditor().analyze([Dependency('PyPI', 'My_Package', '1.0')], [advisory(name='my-package', versions=['1.0'])])
        self.assertEqual(len(report.findings), 1)
    def test_semver_prerelease(self):
        self.assertLess(_compare('npm', '1.0.0-beta.2', '1.0.0-beta.11'), 0)
    def test_semver_release(self):
        self.assertGreater(_compare('npm', '1.0.0', '1.0.0-rc.1'), 0)
    def test_semver_build(self):
        self.assertEqual(_compare('npm', '1.0.0+abc', '1.0.0+xyz'), 0)
    def test_semver_bad(self):
        with self.assertRaises(ValueError):
            _compare('npm', '1.2', '1.2.0')
    def test_semver_numeric_zero(self):
        with self.assertRaises(ValueError):
            _compare('npm', '1.0.0-01', '1.0.0')
    def test_unsupported(self):
        with self.assertRaises(ValueError):
            _compare('Maven', '1', '2')


class RangeTests(unittest.TestCase):
    def test_open_range(self):
        self.assertTrue(_affected('PyPI', '2.0', [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}]}]))
    def test_fixed_exclusive(self):
        events = [{'introduced': '0'}, {'fixed': '2.0'}]
        self.assertTrue(_affected('PyPI', '1.9', [{'type': 'ECOSYSTEM', 'events': events}]))
        self.assertFalse(_affected('PyPI', '2.0', [{'type': 'ECOSYSTEM', 'events': events}]))
    def test_last_affected_inclusive(self):
        events = [{'introduced': '0'}, {'last_affected': '1.5'}]
        self.assertTrue(_affected('PyPI', '1.5', [{'type': 'ECOSYSTEM', 'events': events}]))
        self.assertFalse(_affected('PyPI', '1.6', [{'type': 'ECOSYSTEM', 'events': events}]))
    def test_multiple_intervals(self):
        events = [{'introduced': '1.0'}, {'fixed': '1.5'}, {'introduced': '2.0'}, {'fixed': '2.5'}]
        self.assertTrue(_affected('PyPI', '2.2', [{'type': 'ECOSYSTEM', 'events': events}]))
        self.assertFalse(_affected('PyPI', '1.8', [{'type': 'ECOSYSTEM', 'events': events}]))
    def test_no_ranges_unknown(self):
        self.assertIsNone(_affected('PyPI', '1.0', []))
    def test_unsupported_range_unknown(self):
        self.assertIsNone(_affected('PyPI', '1.0', [{'type': 'GIT', 'events': [{'introduced': '0'}]}]))
    def test_invalid_event_unknown(self):
        self.assertIsNone(_affected('PyPI', '1.0', [{'type': 'ECOSYSTEM', 'events': [{'fixed': 'bad-version-??'}]}]))


class ParserTests(unittest.TestCase):
    def test_requirements_pins(self):
        deps, notes = parse_requirements('requests==2.31.0\n# comment\nflask>=2\n')
        self.assertEqual([(d.name, d.version) for d in deps], [('requests', '2.31.0')])
        self.assertEqual(len(notes), 1)
    def test_requirements_url_skipped(self):
        deps, notes = parse_requirements('https://example.test/a.whl')
        self.assertFalse(deps)
        self.assertTrue(notes)
    def test_lock_v3(self):
        doc = {'lockfileVersion': 3, 'packages': {'': {}, 'node_modules/foo': {'version': '1.2.3'}, 'node_modules/@a/b': {'version': '2.0.0'}}}
        deps, notes = parse_package_lock(json.dumps(doc))
        self.assertEqual({d.name for d in deps}, {'foo', '@a/b'})
    def test_nested_lock(self):
        doc = {'lockfileVersion': 2, 'packages': {'node_modules/a/node_modules/b': {'version': '1.0.0'}}}
        deps, _ = parse_package_lock(json.dumps(doc))
        self.assertEqual(deps[0].name, 'b')
    def test_bad_lock(self):
        with self.assertRaises(InventoryError):
            parse_package_lock('{}')
    def test_bad_json(self):
        with self.assertRaises(InventoryError):
            parse_package_lock('not-json')
    def test_cyclonedx(self):
        doc = {'bomFormat': 'CycloneDX', 'components': [{'purl': 'pkg:pypi/requests@2.31.0'}, {'purl': 'pkg:npm/%40scope/name@1.0.0'}]}
        deps, _ = parse_cyclonedx(json.dumps(doc))
        self.assertEqual(len(deps), 2)
        self.assertEqual(deps[1].name, '@scope/name')
    def test_cyclonedx_invalid(self):
        with self.assertRaises(InventoryError):
            parse_cyclonedx('{}')
    def test_cyclonedx_skip(self):
        deps, notes = parse_cyclonedx(json.dumps({'bomFormat': 'CycloneDX', 'components': [{'name': 'unknown'}]}))

