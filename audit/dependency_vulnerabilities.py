"""Muninn offline dependency vulnerability auditor.

Inputs are trusted dependency inventories and advisory feeds, not target traffic.
No network access or code execution. Requires `packaging` for PEP 440 version
comparisons; npm comparisons use strict numeric SemVer (including prereleases).

Only positive matches against explicit affected ranges become findings. Unknown
or malformed versions are reported as diagnostics, never as vulnerabilities.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
import json
import re
from typing import Any, Iterable, Mapping

try:
    from packaging.version import Version, InvalidVersion
except ImportError:  # explicit diagnostic when used
    Version = InvalidVersion = None

MAX_ITEMS = 100_000
MAX_ADVISORIES = 100_000
MAX_FINDINGS = 10_000


class InventoryError(ValueError):
    pass


@dataclass(frozen=True)
class Dependency:
    ecosystem: str
    name: str
    version: str
    direct: bool | None = None
    source: str = "inventory"


@dataclass(frozen=True)
class Finding:
    advisory_id: str
    ecosystem: str
    package: str
    version: str
    severity: str
    source: str
    evidence: str
    aliases: tuple[str, ...] = ()


@dataclass
class AuditReport:
    dependencies: int = 0
    advisories: int = 0
    findings: list[Finding] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"dependencies": self.dependencies, "advisories": self.advisories,
                "findings": [asdict(f) for f in self.findings],
                "diagnostics": sorted(set(self.diagnostics))}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def _ecosystem(value: str) -> str:
    aliases = {"python": "PyPI", "pypi": "PyPI", "npm": "npm"}
    return aliases.get(str(value).strip().lower(), "")


def _name(ecosystem: str, name: str) -> str:
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem == "npm":
        return name.lower()  # npm names are case-insensitive
    return name


def _safe_identifier(value: Any, limit: int = 160) -> str:
    value = str(value)
    if not value or len(value) > limit or not re.fullmatch(r"[\w@./:+-]+", value, re.ASCII):
        raise InventoryError("invalid identifier")
    return value


def _semver(value: str) -> tuple[int, int, int, tuple[Any, ...]]:
    match = re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?", value)
    if not match:
        raise ValueError("not a strict SemVer version")
    major, minor, patch = map(int, value.split("-")[0].split("+")[0].split("."))
    pre = match.group(1)
    parts = () if pre is None else tuple(pre.split("."))
    if any(not p or (p.isdigit() and len(p) > 1 and p[0] == "0") for p in parts):
        raise ValueError("invalid prerelease")
    return major, minor, patch, parts


def _compare(ecosystem: str, a: str, b: str) -> int:
    if ecosystem == "PyPI":
        if Version is None:
            raise ValueError("install 'packaging' for PyPI version comparison")
        try:
            va, vb = Version(a), Version(b)
        except InvalidVersion as exc:
            raise ValueError("invalid PEP 440 version") from exc
        return (va > vb) - (va < vb)
    if ecosystem != "npm":
        raise ValueError("unsupported ecosystem")
    aa, bb = _semver(a), _semver(b)
    if aa[:3] != bb[:3]:
        return (aa[:3] > bb[:3]) - (aa[:3] < bb[:3])
    x, y = aa[3], bb[3]
    if not x or not y:
        return (not x) - (not y)
    for left, right in zip(x, y):
        if left == right:
            continue
        ln, rn = left.isdigit(), right.isdigit()
        if ln != rn:
            return -1 if ln else 1
        if ln:
            return (int(left) > int(right)) - (int(left) < int(right))
        return (left > right) - (left < right)
    return (len(x) > len(y)) - (len(x) < len(y))


def _affected(ecosystem: str, version: str, ranges: list[dict[str, Any]]) -> bool | None:
    """OSV event intervals; None means insufficient/unsupported evidence."""
    if not ranges:
        return None
    uncertain = False
    for item in ranges:
        if not isinstance(item, dict) or item.get("type") != "ECOSYSTEM":
            uncertain = True
            continue
        events = item.get("events")
        if not isinstance(events, list) or not events:
            uncertain = True
            continue
        active = False
        valid = True
        for event in events:
            if not isinstance(event, dict) or len(event) != 1:
                valid = False
                break
            kind, boundary = next(iter(event.items()))
            if kind not in ("introduced", "fixed", "last_affected") or not isinstance(boundary, str):
                valid = False
                break
            try:
                cmp = 1 if kind == "introduced" and boundary == "0" else _compare(ecosystem, version, boundary)
            except ValueError:
                valid = False
                break
            if kind == "introduced" and cmp >= 0:
                active = True
            elif kind == "fixed" and cmp >= 0:
                active = False
            elif kind == "last_affected" and cmp > 0:
                active = False
        if not valid:
            uncertain = True
        elif active:
            return True
    return None if uncertain else False


def _advisory_match(dep: Dependency, advisory: Mapping[str, Any]) -> bool | None:
    results = []
    for entry in advisory.get("affected", []):
        if not isinstance(entry, dict):
            continue
        package = entry.get("package", {})
        if not isinstance(package, dict):
            continue
        eco = _ecosystem(package.get("ecosystem", ""))
        name = package.get("name", "")
        if eco != dep.ecosystem or not isinstance(name, str) or _name(eco, name) != _name(dep.ecosystem, dep.name):
            continue
        versions = entry.get("versions", [])
        if isinstance(versions, list) and dep.version in versions:
            return True
        result = _affected(eco, dep.version, entry.get("ranges", []))
        results.append(result)
    if True in results:
        return True
    if None in results:
        return None
    return False


def parse_requirements(text: str) -> tuple[list[Dependency], list[str]]:
    """Only exact == pins; intentionally skip includes, URLs and constraints."""
    dependencies, diagnostics = [], []
    for line_number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s;#]+)(?:\s*#.*)?", line)
        if not match:
            diagnostics.append(f"requirements line {line_number}: skipped non-exact or unsupported specification")
            continue
        dependencies.append(Dependency("PyPI", match.group(1), match.group(2), True, "requirements"))
    return dependencies, diagnostics


def parse_package_lock(text: str) -> tuple[list[Dependency], list[str]]:
    try:
        document = json.loads(text)
    except (ValueError, TypeError) as exc:
        raise InventoryError("invalid package-lock JSON") from exc
    if not isinstance(document, dict) or document.get("lockfileVersion") not in (2, 3):
        raise InventoryError("requires npm package-lock v2 or v3")
    packages = document.get("packages")
    if not isinstance(packages, dict):
        raise InventoryError("missing packages map")
    deps, notes = [], []
    for path, meta in packages.items():
        if path == "":
            continue
        if not isinstance(path, str) or not isinstance(meta, dict):
            notes.append("skipped malformed package-lock entry")
            continue
        version = meta.get("version")
        if not isinstance(version, str):
            notes.append("skipped package-lock entry without resolved version")
            continue
        match = re.search(r"(?:^|/)node_modules/((?:@[^/]+/)?[^/]+)$", path)
        if not match:
            notes.append("skipped non-node_modules package-lock entry")
            continue
        deps.append(Dependency("npm", match.group(1), version, None, "package-lock"))
    return deps, notes


def parse_cyclonedx(text: str) -> tuple[list[Dependency], list[str]]:
    try:
        document = json.loads(text)
    except (ValueError, TypeError) as exc:
        raise InventoryError("invalid CycloneDX JSON") from exc
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise InventoryError("not a CycloneDX BOM")
    components = document.get("components", [])
    if not isinstance(components, list):
        raise InventoryError("invalid CycloneDX components")
    deps, notes = [], []
    for component in components:
        if not isinstance(component, dict):
            notes.append("skipped malformed component")
            continue
        purl = component.get("purl", "")
        match = re.fullmatch(r"pkg:(pypi|npm)/([^?#]+)@([^?#]+)(?:\?[^#]*)?(?:#.*)?", purl, re.I) if isinstance(purl, str) else None
        if not match:
            notes.append("skipped component without supported versioned purl")
            continue
        from urllib.parse import unquote
        eco, name, version = match.groups()
        deps.append(Dependency(_ecosystem(eco), unquote(name), unquote(version), None, "cyclonedx"))
    return deps, notes


class DependencyVulnerabilityAuditor:
    def __init__(self, max_dependencies: int = MAX_ITEMS, max_advisories: int = MAX_ADVISORIES,
                 max_findings: int = MAX_FINDINGS):
        if min(max_dependencies, max_advisories, max_findings) < 1:
            raise ValueError("limits must be positive")
        self.max_dependencies = max_dependencies
        self.max_advisories = max_advisories
        self.max_findings = max_findings

    def analyze(self, dependencies: Iterable[Dependency], advisories: Iterable[Mapping[str, Any]]) -> AuditReport:
        report = AuditReport()
        inventory = {}
        for dep in dependencies:
            report.dependencies += 1
            if report.dependencies > self.max_dependencies:
                raise InventoryError("dependency limit exceeded")
            if not isinstance(dep, Dependency):
                raise InventoryError("invalid dependency")
            eco = _ecosystem(dep.ecosystem)
            if not eco:
                report.diagnostics.append("unsupported dependency ecosystem")
                continue
            try:
                _safe_identifier(dep.name)
                _safe_identifier(dep.version)
                _compare(eco, dep.version, dep.version)
            except (InventoryError, ValueError):
                report.diagnostics.append(f"skipped invalid or uncomparable version for {eco} package")
                continue
            normalized = Dependency(eco, _name(eco, dep.name), dep.version, dep.direct, dep.source)
            inventory[(eco, normalized.name, normalized.version)] = normalized
        advisory_list = []
        for advisory in advisories:
            report.advisories += 1
            if report.advisories > self.max_advisories:
                raise InventoryError("advisory limit exceeded")
            if not isinstance(advisory, Mapping):
                report.diagnostics.append("skipped malformed advisory")
                continue
            try:
                aid = _safe_identifier(advisory.get("id", ""))
            except InventoryError:
                report.diagnostics.append("skipped advisory without valid ID")
                continue
            if not isinstance(advisory.get("affected", []), list):
                report.diagnostics.append("skipped advisory with invalid affected data")
                continue
            advisory_list.append((aid, advisory))
        seen = set()
        for dep in sorted(inventory.values(), key=lambda x: (x.ecosystem, x.name, x.version)):
            for aid, advisory in sorted(advisory_list, key=lambda x: x[0]):
                match = _advisory_match(dep, advisory)
                if match is None:
                    report.diagnostics.append(f"inconclusive range evaluation for advisory {aid}")
                    continue
                if not match:
                    continue
                key = (aid, dep.ecosystem, dep.name, dep.version)
                if key in seen:
                    continue
                seen.add(key)
                if len(report.findings) >= self.max_findings:
                    raise InventoryError("finding limit exceeded")
                aliases = advisory.get("aliases", [])
                safe_aliases = tuple(sorted({a for a in aliases if isinstance(a, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", a)})) if isinstance(aliases, list) else ()
                report.findings.append(Finding(
                    advisory_id=aid, ecosystem=dep.ecosystem, package=dep.name,
                    version=dep.version, severity="unverified",
                    source=dep.source, evidence="Installed/resolved version matches advisory affected range or exact version list",
                    aliases=safe_aliases))
        return report


__all__ = ["Dependency", "Finding", "AuditReport", "InventoryError", "DependencyVulnerabilityAuditor",
           "parse_requirements", "parse_package_lock", "parse_cyclonedx"]
