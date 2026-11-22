#!/usr/bin/env python3
"""
cve_index.py — Build and query a fast local index of CVE data.

Reads CVE_Lists/<year>/*.json (cvelistV5 or NVD 2.0 format), recursively,
optionally compressed with .gz. Writes CVE_Lists/_index.json.

Usage:
    python3 cve_index.py build                   # build/refresh index
    python3 cve_index.py build --force           # rebuild
    python3 cve_index.py build --verbose         # show every file
    python3 cve_index.py diagnose                # explain what's in CVE_Lists/
    python3 cve_index.py stats                   # index statistics
    python3 cve_index.py query apache            # query by product
    python3 cve_index.py query nginx --version 1.18.0
    python3 cve_index.py cve CVE-2021-41773      # show one CVE fully
"""
import argparse
import gzip
import json
import os
import re
import sys
import time
from pathlib import Path

CVE_DIR = "CVE_Lists"
INDEX_PATH = os.path.join(CVE_DIR, "_index.json")
INDEX_VERSION = 1


# ─────────────────────────────────────────────────────────────────────
# Version comparison
# ─────────────────────────────────────────────────────────────────────
def compare_versions(a: str, b: str) -> int:
    """Return -1 if a < b, 0 if equal, 1 if a > b. Best-effort."""
    if a == b:
        return 0
    try:
        from packaging.version import Version
        va, vb = Version(a), Version(b)
        return (va > vb) - (va < vb)
    except Exception:
        pass
    def tokenize(v):
        parts = re.split(r"[.\-+_ rp]", v.lower())
        return [int(p) if p.isdigit() else p for p in parts if p]
    ta, tb = tokenize(a), tokenize(b)
    for i in range(max(len(ta), len(tb))):
        pa = ta[i] if i < len(ta) else 0
        pb = tb[i] if i < len(tb) else 0
        if pa == pb:
            continue
        if isinstance(pa, int) != isinstance(pb, int):
            pa, pb = str(pa), str(pb)
        return -1 if pa < pb else 1
    return 0


def version_matches(target: str, version_rules: list) -> bool:
    for rule in version_rules:
        if rule.get("status") == "unaffected" and rule.get("version") == target:
            return False
    for rule in version_rules:
        if rule.get("status") != "affected":
            continue
        start = rule.get("version")
        end_le = rule.get("lessThanOrEqual")
        end_lt = rule.get("lessThan")
        try:
            if start and compare_versions(target, start) < 0:
                continue
            if end_le and compare_versions(target, end_le) > 0:
                continue
            if end_lt and compare_versions(target, end_lt) >= 0:
                continue
            return True
        except Exception:
            continue
    return False


# ─────────────────────────────────────────────────────────────────────
# File reading — plain and gzip
# ─────────────────────────────────────────────────────────────────────
def read_json_file(path: Path):
    """Read JSON from .json or .json.gz. Returns (doc, error_reason)."""
    try:
        if path.suffix == ".gz":
            with gzip.open(path, "rb") as f:
                raw = f.read()
        else:
            with open(path, "rb") as f:
                raw = f.read()
    except OSError as e:
        return None, f"read-error: {e}"
    try:
        return json.loads(raw), None
    except json.JSONDecodeError as e:
        return None, f"bad-json: {e.msg} at line {e.lineno} col {e.colno}"
    except Exception as e:
        return None, f"parse-error: {e}"


# ─────────────────────────────────────────────────────────────────────
# CVE extraction — cvelistV5 (primary) + NVD 2.0 (fallback)
# ─────────────────────────────────────────────────────────────────────
def extract_cvelistv5(doc: dict):
    meta = doc.get("cveMetadata", {})
    cve_id = meta.get("cveId")
    if not cve_id:
        return None, "missing-cveMetadata.cveId"
    state = meta.get("state")
    if state != "PUBLISHED":
        return None, f"state-{state or 'missing'}"
    cna = doc.get("containers", {}).get("cna", {})
    adp_list = doc.get("containers", {}).get("adp", []) or []

    cvss_score, cvss_vector, severity = None, None, None
    for adp in adp_list:
        for metric in adp.get("metrics", []) or []:
            v31 = metric.get("cvssV3_1") or metric.get("cvssV3_0") or metric.get("cvssV4_0")
            if v31:
                cvss_score = v31.get("baseScore")
                cvss_vector = v31.get("vectorString")
                severity = v31.get("baseSeverity")
                break
        if cvss_score is not None:
            break

    cwes = []
    for pt in cna.get("problemTypes", []) or []:
        for d in pt.get("descriptions", []) or []:
            if d.get("cweId"):
                cwes.append(d["cweId"])

    affected = []
    for a in cna.get("affected", []) or []:
        vendor = (a.get("vendor") or "").strip()
        product = (a.get("product") or "").strip()
        if not product:
            continue
        versions = [{
            "status": v.get("status"),
            "version": v.get("version"),
            "lessThanOrEqual": v.get("lessThanOrEqual"),
            "lessThan": v.get("lessThan"),
            "versionType": v.get("versionType"),
        } for v in (a.get("versions") or [])]
        affected.append({"vendor": vendor, "product": product, "versions": versions})

    desc = ""
    for d in cna.get("descriptions", []) or []:
        if d.get("lang", "").lower().startswith("en"):
            desc = d.get("value", "")
            break

    return {
        "id": cve_id,
        "published": (meta.get("datePublished") or "")[:10],
        "updated": (meta.get("dateUpdated") or "")[:10],
        "assigner": meta.get("assignerShortName"),
        "title": cna.get("title", ""),
        "cvss": cvss_score,
        "cvss_vector": cvss_vector,
        "severity": severity,
        "cwe": cwes,
        "description": desc[:800],
        "affected": affected,
        "references": [r.get("url") for r in (cna.get("references") or []) if r.get("url")][:8],
    }, None


def extract_nvd20(doc: dict):
    cve = doc.get("cve", {})
    cve_id = cve.get("id")
    if not cve_id:
        return None, "missing-cve.id"

    cvss_score, cvss_vector, severity = None, None, None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key, []) or []:
            data = m.get("cvssData", {})
            if data.get("baseScore") is not None:
                cvss_score = data["baseScore"]
                cvss_vector = data.get("vectorString")
                severity = data.get("baseSeverity") or m.get("baseSeverity")
                break
        if cvss_score is not None:
            break

    cwes = []
    for w in cve.get("weaknesses", []) or []:
        for d in w.get("description", []) or []:
            if d.get("value", "").startswith("CWE-"):
                cwes.append(d["value"])

    affected = []
    for cfg in cve.get("configurations", []) or []:
        for node in cfg.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                parts = (match.get("criteria") or "").split(":")
                if len(parts) < 6:
                    continue
                vendor = parts[3].replace("_", " ")
                product = parts[4].replace("_", " ")
                version = parts[5]
                rule = {"status": "affected" if match.get("vulnerable") else "unaffected"}
                if version and version != "*":
                    rule["version"] = version
                if match.get("versionEndIncluding"):
                    rule.setdefault("version", "0")
                    rule["lessThanOrEqual"] = match["versionEndIncluding"]
                if match.get("versionEndExcluding"):
                    rule.setdefault("version", "0")
                    rule["lessThan"] = match["versionEndExcluding"]
                if vendor and product:
                    affected.append({"vendor": vendor, "product": product, "versions": [rule]})

    desc = ""
    for d in cve.get("descriptions", []) or []:
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break

    return {
        "id": cve_id,
        "published": (cve.get("published") or "")[:10],
        "updated": (cve.get("lastModified") or "")[:10],
        "assigner": cve.get("sourceIdentifier"),
        "title": "",
        "cvss": cvss_score,
        "cvss_vector": cvss_vector,
        "severity": severity,
        "cwe": cwes,
        "description": desc[:800],
        "affected": affected,
        "references": [r.get("url") for r in (cve.get("references") or [])][:8],
    }, None


def extract_cve(path: Path):
    """Returns (cve_dict, None) on success, or (None, reason) on skip."""
    doc, err = read_json_file(path)
    if err:
        return None, err

    data_type = doc.get("dataType")
    if data_type == "CVE_RECORD":
        return extract_cvelistv5(doc)
    if isinstance(doc.get("cve"), dict):
        return extract_nvd20(doc)
    if data_type:
        return None, f"unknown-dataType:{data_type}"
    return None, "unrecognized-format"


# ─────────────────────────────────────────────────────────────────────
# File discovery — recursive, includes .json and .json.gz
# ─────────────────────────────────────────────────────────────────────
def find_cve_files(directory: Path) -> list[Path]:
    """Recursively find .json and .json.gz files under directory."""
    out = []
    for p in directory.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix == ".json" or (p.suffix == ".gz" and p.stem.endswith(".json")):
            if p.name.startswith("_"):
                continue  # skip our own index
            out.append(p)
    return sorted(out)


# ─────────────────────────────────────────────────────────────────────
# Build
# ─────────────────────────────────────────────────────────────────────
def build_index(cve_dir: str = CVE_DIR, force: bool = False, verbose: bool = False) -> None:
    root = Path(cve_dir)
    if not root.is_dir():
        print(f"[!] Directory not found: {cve_dir}")
        sys.exit(1)

    if os.path.exists(INDEX_PATH) and not force:
        size_mb = os.path.getsize(INDEX_PATH) / 1024 / 1024
        print(f"[*] Index exists: {INDEX_PATH} ({size_mb:.1f} MB)")
        print("[*] Use --force to rebuild, or run 'diagnose' to see what's there.")
        return

    index = {}
    parsed = skipped = 0
    skip_reasons: dict[str, int] = {}
    t0 = time.time()

    subdirs = sorted([d for d in root.iterdir() if d.is_dir()])
    if not subdirs:
        print(f"[!] No subdirectories under {cve_dir}/")
        print(f"[!] Run 'python3 cve_index.py diagnose' for details.")
        return

    for i, sub in enumerate(subdirs, 1):
        files = find_cve_files(sub)
        if not files:
            print(f"[{i}/{len(subdirs)}] {sub.name:<10} empty")
            continue
        print(f"[{i}/{len(subdirs)}] {sub.name:<10} {len(files)} file(s)", end="", flush=True)
        dir_parsed = 0
        for f in files:
            cve, reason = extract_cve(f)
            if cve:
                index[cve["id"]] = cve
                parsed += 1
                dir_parsed += 1
                if verbose:
                    print(f"\n    ✓ {f.name} → {cve['id']}", end="", flush=True)
            else:
                skipped += 1
                skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
                if verbose:
                    print(f"\n    ✗ {f.name} ({reason})", end="", flush=True)
        print(f" → {dir_parsed} indexed", flush=True)

    elapsed = time.time() - t0
    if parsed == 0:
        print()
        print("[!] ══════════════════════════════════════════════════════")
        print("[!] Indexed 0 CVEs. Your CVE_Lists/ directory is empty")
        print("[!] or contains only unrecognized files.")
        print("[!] Run: python3 cve_index.py diagnose   for details.")
        print("[!] ══════════════════════════════════════════════════════")
        if skip_reasons:
            print("[!] Skip reasons:")
            for reason, count in sorted(skip_reasons.items(), key=lambda x: -x[1]):
                print(f"[!]   {count:>6} × {reason}")
        return

    meta = {"_version": INDEX_VERSION, "_built": int(time.time()), "_count": len(index)}
    with open(INDEX_PATH, "w", encoding="utf-8") as f:
        json.dump({**meta, "cves": index}, f, separators=(",", ":"))

    size_mb = os.path.getsize(INDEX_PATH) / 1024 / 1024
    print(f"\n[+] Indexed {parsed} CVEs, skipped {skipped}")
    print(f"[+] Output: {INDEX_PATH} ({size_mb:.1f} MB)")
    print(f"[+] Build time: {elapsed:.1f}s")
    if skip_reasons:
        print(f"[*] Top skip reasons:")
        for reason, count in sorted(skip_reasons.items(), key=lambda x: -x[1])[:5]:
            print(f"[*]   {count:>6} × {reason}")


# ─────────────────────────────────────────────────────────────────────
# Diagnose
# ─────────────────────────────────────────────────────────────────────
def cmd_diagnose(cve_dir: str = CVE_DIR) -> None:
    root = Path(cve_dir)
    if not root.is_dir():
        print(f"[!] Directory not found: {cve_dir}")
        return

    print(f"Diagnosing {cve_dir}/\n")

    subdirs = sorted([d for d in root.iterdir() if d.is_dir()])
    total_files = 0
    total_bytes = 0
    skipped_examples = []

    for sub in subdirs:
        files = find_cve_files(sub)
        if not files:
            print(f"  {sub.name + '/':<18}   0 files    (EMPTY)")
            continue
        size = sum(f.stat().st_size for f in files)
        total_bytes += size
        total_files += len(files)
        sample = ""
        if files:
            first = files[0]
            cve, reason = extract_cve(first)
            if cve:
                sample = f"sample OK: {cve['id']}"
            else:
                sample = f"sample SKIPPED: {reason}"
                skipped_examples.append((first, reason))
        print(f"  {sub.name + '/':<18} {len(files):>4} file(s)  "
              f"{size/1024/1024:>7.2f} MB   {sample}")

    print(f"\n  Total: {total_files} files, {total_bytes/1024/1024:.2f} MB")

    if total_files == 0:
        print("\n[!] ─────────────────────────────────────────────────────")
        print("[!] CVE_Lists/ is empty.")
        print("[!]")
        print("[!] Download CVEs from one of these sources:")
        print("[!]   • Official CVE Program (recommended, cvelistV5 format):")
        print("[!]       git clone --depth 1 https://github.com/CVEProject/cvelistV5.git")
        print("[!]       # then copy cvelistV5/cves/<year>/* into CVE_Lists/<year>/")
        print("[!]   • NVD 2.0 bulk (also supported, larger):")
        print("[!]       https://nvd.nist.gov/vuln/data-feeds#div-29541391")
        print("[!] ─────────────────────────────────────────────────────")
        return

    if skipped_examples:
        print(f"\n[*] {len(skipped_examples)} sample file(s) that would be skipped:")
        for path, reason in skipped_examples[:10]:
            size = path.stat().st_size / 1024
            print(f"    {path}  ({size:.1f} KB)")
            print(f"      reason: {reason}")


# ─────────────────────────────────────────────────────────────────────
# Query
# ─────────────────────────────────────────────────────────────────────
def load_index() -> dict:
    if not os.path.exists(INDEX_PATH):
        print(f"[!] No index at {INDEX_PATH}. Run 'python3 cve_index.py build' first.")
        sys.exit(1)
    with open(INDEX_PATH, "r", encoding="utf-8") as f:
        return json.load(f)["cves"]


def normalize_product(s: str) -> list[str]:
    s = s.lower()
    s = re.sub(r"\b(inc|corp|corporation|ltd|llc|co|company|the)\b", "", s)
    return [t for t in re.findall(r"[a-z0-9]+", s) if len(t) > 1]


def products_match(a_tokens: list[str], b_tokens: list[str]) -> bool:
    if not a_tokens or not b_tokens:
        return False
    set_a, set_b = set(a_tokens), set(b_tokens)
    overlap = set_a & set_b
    if len(overlap) >= 2:
        return True
    if len(overlap) == 1 and len(set_a) <= 2 and len(set_b) <= 2:
        return True
    return False


def query_product(index: dict, product: str, version: str | None = None,
                  min_cvss: float | None = None) -> list[dict]:
    target_tokens = normalize_product(product)
    matches = []
    for cve in index.values():
        if min_cvss is not None and (cve.get("cvss") or 0) < min_cvss:
            continue
        for aff in cve.get("affected", []):
            if not products_match(target_tokens, normalize_product(aff.get("product", ""))):
                continue
            if version and not version_matches(version, aff.get("versions", [])):
                continue
            matches.append(cve)
            break
    matches.sort(key=lambda c: (c.get("cvss") or 0, c.get("published") or ""), reverse=True)
    return matches


# ─────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────
def cmd_stats(index: dict) -> None:
    total = len(index)
    if total == 0:
        print("Index is empty. Run 'python3 cve_index.py build' first.")
        return
    with_cvss = sum(1 for c in index.values() if c.get("cvss") is not None)
    with_cwe = sum(1 for c in index.values() if c.get("cwe"))
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for c in index.values():
        sev = (c.get("severity") or "UNKNOWN").upper()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
    print(f"Total CVEs:        {total:,}")
    print(f"With CVSS score:   {with_cvss:,} ({with_cvss/total*100:.1f}%)")
    print(f"With CWE:          {with_cwe:,} ({with_cwe/total*100:.1f}%)")
    print(f"Severity breakdown:")
    for sev, cnt in sev_counts.items():
        if cnt:
            print(f"  {sev:<10} {cnt:,}")


def cmd_query(index: dict, product: str, version: str | None, limit: int) -> None:
    matches = query_product(index, product, version)
    if not matches:
        print(f"No CVEs found for product '{product}'"
              + (f" version {version}" if version else ""))
        return
    print(f"{len(matches)} CVE(s) for '{product}'"
          + (f" v{version}" if version else "") + ":\n")
    for cve in matches[:limit]:
        sev = cve.get("severity") or "UNKNOWN"
        score = f"{cve['cvss']:.1f}" if cve.get("cvss") is not None else "N/A"
        title = cve.get("title") or cve.get("description", "")[:80]
        print(f"{cve['id']:<18} {sev:<9} {score:<4}  {title}")
        print(f"  published: {cve.get('published') or '?'}   "
              f"cwe: {','.join(cve.get('cwe') or []) or '-'}")
        if cve.get("references"):
            print(f"  ref: {cve['references'][0]}")
        print()
    if len(matches) > limit:
        print(f"... and {len(matches) - limit} more (use --limit to see all)")


def cmd_show(index: dict, cve_id: str) -> None:
    cve = index.get(cve_id)
    if not cve:
        print(f"Not found: {cve_id}")
        return
    print(f"ID:          {cve['id']}")
    print(f"Published:   {cve.get('published')}")
    print(f"Severity:    {cve.get('severity')} (CVSS {cve.get('cvss')})")
    print(f"Vector:      {cve.get('cvss_vector')}")
    print(f"CWE:         {', '.join(cve.get('cwe') or [])}")
    print(f"Title:       {cve.get('title')}")
    print(f"\nAffected:")
    for a in cve.get("affected", []):
        print(f"  {a['vendor']} / {a['product']}")
        for v in a.get("versions", []):
            tail = ""
            if v.get("lessThanOrEqual"):
                tail = f" <= {v['lessThanOrEqual']}"
            elif v.get("lessThan"):
                tail = f" < {v['lessThan']}"
            print(f"    - {v.get('status')}: {v.get('version')}{tail}")
    print(f"\n{cve.get('description', '')}")
    if cve.get("references"):
        print(f"\nReferences:")
        for r in cve["references"]:
            print(f"  {r}")


def main():
    p = argparse.ArgumentParser(description="Muninn CVE index builder/query")
    p.add_argument("--cve-dir", default=CVE_DIR)
    sub = p.add_subparsers(dest="cmd", required=True)

    build = sub.add_parser("build", help="Build/refresh the CVE index")
    build.add_argument("--force", action="store_true")
    build.add_argument("--verbose", action="store_true", help="Log every file")

    sub.add_parser("diagnose", help="Explain what's in CVE_Lists/")
    sub.add_parser("stats", help="Show index statistics")

    q = sub.add_parser("query", help="Query CVEs by product name")
    q.add_argument("product")
    q.add_argument("--version", default=None)
    q.add_argument("--limit", type=int, default=20)

    s = sub.add_parser("cve", help="Show a single CVE in detail")
    s.add_argument("cve_id")

    args = p.parse_args()

    if args.cmd == "build":
        build_index(args.cve_dir, force=args.force, verbose=args.verbose)
    elif args.cmd == "diagnose":
        cmd_diagnose(args.cve_dir)
    else:
        index = load_index()
        if args.cmd == "stats":
            cmd_stats(index)
        elif args.cmd == "query":
            cmd_query(index, args.product, args.version, args.limit)
        elif args.cmd == "cve":
            cmd_show(index, args.cve_id)


if __name__ == "__main__":
    main()
