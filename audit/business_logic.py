"""Muninn business-logic auditor: offline, policy-driven workflow invariant checks.

No network operations. Caller supplies trusted scenario expectations and scoped,
redacted observations. All findings are hypotheses until independently verified.
Python >=3.10, standard library only.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from decimal import Decimal, InvalidOperation
from hashlib import sha256
from typing import Any, Callable, Iterable, Mapping
import json
import re
from urllib.parse import urlsplit


class ValidationError(ValueError):
    """Invalid audit input or policy."""


@dataclass(frozen=True)
class Event:
    scenario: str
    step: str
    sequence: int
    method: str
    url: str
    status: int
    actor: str = ""
    role: str = ""
    resource: str = ""
    correlation: str = ""
    # Trusted, sanitized fixture facts, not arbitrary HTTP response data.
    facts: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Rule:
    id: str
    kind: str
    scenario: str
    severity: str = "medium"
    # step / fact / expected / prior_step / limit / operation / allowed_roles
    config: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    kind: str
    severity: str
    scenario_hash: str
    message: str
    evidence_steps: tuple[str, ...]
    confidence: str = "indicator"


@dataclass(frozen=True)
class Report:
    examined: int
    scoped: int
    evaluated_rules: int
    findings: tuple[Finding, ...]
    skipped: int
    diagnostics: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


_ALLOWED_KINDS = frozenset({
    "required_predecessor", "allowed_transition", "unique_success",
    "maximum_successes", "fact_equals", "decimal_balance", "role_gate",
    "idempotency", "monotonic_fact", "cross_actor_success",
})
_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})
_NAME = re.compile(r"^[A-Za-z0-9_.:-]{1,100}$")
_MAX_FACTS = 32


def _digest(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()[:16]


def _decimal(value: Any) -> Decimal:
    if isinstance(value, bool) or value is None or isinstance(value, float):
        raise ValidationError("Money values must be decimal strings or integers")
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValidationError("Invalid decimal value") from exc
    if not result.is_finite() or abs(result.as_tuple().exponent) > 12:
        raise ValidationError("Non-finite or excessive-precision decimal")
    return result


def _safe_fact(v: Any) -> bool:
    return (v is None or isinstance(v, (str, int, bool))) and (
        not isinstance(v, str) or len(v) <= 256
    )


def _validate_event(e: Event) -> None:
    if not isinstance(e, Event):
        raise ValidationError("Expected Event")
    if not all(_NAME.fullmatch(v) for v in (e.scenario, e.step)):
        raise ValidationError("Invalid scenario or step name")
    if not isinstance(e.sequence, int) or isinstance(e.sequence, bool) or e.sequence < 0:
        raise ValidationError("Invalid sequence")
    if e.method.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        raise ValidationError("Invalid method")
    if not isinstance(e.status, int) or isinstance(e.status, bool) or not 100 <= e.status <= 599:
        raise ValidationError("Invalid status")
    parsed = urlsplit(e.url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValidationError("Invalid URL")
    if not isinstance(e.facts, Mapping) or len(e.facts) > _MAX_FACTS:
        raise ValidationError("Invalid facts")
    for key, value in e.facts.items():
        if not isinstance(key, str) or not _NAME.fullmatch(key) or not _safe_fact(value):
            raise ValidationError("Invalid fact; supply only sanitized scalar fixture facts")


def _validate_rule(r: Rule) -> None:
    if not isinstance(r, Rule) or not _NAME.fullmatch(r.id) or not _NAME.fullmatch(r.scenario):
        raise ValidationError("Invalid rule")
    if r.kind not in _ALLOWED_KINDS or r.severity not in _SEVERITIES:
        raise ValidationError("Unsupported rule kind or severity")
    if not isinstance(r.config, Mapping):
        raise ValidationError("Invalid rule config")


class BusinessLogicAuditor:
    """Offline analysis of explicitly authorized, pre-collected workflow events.

    Rule kinds:
      required_predecessor: step, prior_step
      allowed_transition: from_step, to_step (flag if transition observed)
      unique_success: step (per resource+correlation, more than one 2xx)
      maximum_successes: step, limit (per resource+correlation)
      fact_equals: step, fact, expected
      decimal_balance: step, before, delta, after (before+delta == after)
      role_gate: step, allowed_roles
      idempotency: step, key_fact, result_fact (same key, differing results)
      monotonic_fact: step, fact, direction ('nondecreasing'/'nonincreasing')
      cross_actor_success: step (more than one actor succeeds on same resource)

    Rules only evaluate *observed* evidence. Missing observations are not proof
    of missing enforcement. Invariants should be based on trusted test fixtures.
    """

    def __init__(self, *, max_events: int = 10000, max_rules: int = 200,
                 max_findings: int = 1000):
        if any(not isinstance(v, int) or isinstance(v, bool) or v < 1
               for v in (max_events, max_rules, max_findings)):
            raise ValidationError("Limits must be positive integers")
        self.max_events = max_events
        self.max_rules = max_rules
        self.max_findings = max_findings

    def analyze(self, events: Iterable[Event], rules: Iterable[Rule], *,
                scope_check: Callable[[str], bool]) -> Report:
        if not callable(scope_check):
            raise ValidationError("Explicit scope_check callback required")
        all_rules = []
        for rule in rules:
            if len(all_rules) >= self.max_rules:
                raise ValidationError("Rule limit exceeded")
            _validate_rule(rule)
            all_rules.append(rule)
        if len({r.id for r in all_rules}) != len(all_rules):
            raise ValidationError("Duplicate rule IDs")
        scoped: list[Event] = []
        examined = skipped = 0
        for e in events:
            if examined >= self.max_events:
                raise ValidationError("Event limit exceeded")
            examined += 1
            _validate_event(e)
            try:
                allowed = scope_check(e.url) is True
            except Exception:
                allowed = False
            if allowed:
                scoped.append(e)
            else:
                skipped += 1
        scoped.sort(key=lambda e: (e.scenario, e.sequence, e.step, e.actor, e.resource))
        groups: dict[str, list[Event]] = {}
        for e in scoped:
            groups.setdefault(e.scenario, []).append(e)
        findings: list[Finding] = []
        diagnostics: list[str] = []
        for rule in sorted(all_rules, key=lambda r: r.id):
            items = groups.get(rule.scenario, [])
            if not items:
                diagnostics.append(f"Rule {rule.id}: no scoped evidence")
                continue
            matches = self._evaluate(rule, items)
            for message, steps in matches:
                if len(findings) >= self.max_findings:
                    diagnostics.append("Finding limit reached; results truncated")
                    return Report(examined, len(scoped), len(all_rules),
                                  tuple(findings), skipped, tuple(diagnostics))
                findings.append(Finding(rule.id, rule.kind, rule.severity,
                                        _digest(rule.scenario), message, tuple(steps)))
        return Report(examined, len(scoped), len(all_rules),
                      tuple(findings), skipped, tuple(diagnostics))

    @staticmethod
    def _evaluate(rule: Rule, items: list[Event]) -> list[tuple[str, tuple[str, ...]]]:
        c = rule.config
        kind = rule.kind
        out: list[tuple[str, tuple[str, ...]]] = []
        def need(*names: str) -> None:
            if any(name not in c for name in names):
                raise ValidationError(f"Rule {rule.id} missing required configuration")
        def successes(step: str) -> list[Event]:
            return [e for e in items if e.step == step and 200 <= e.status < 300]
        if kind == "required_predecessor":
            need("step", "prior_step")
            for e in successes(c["step"]):
                if not any(p.step == c["prior_step"] and p.sequence < e.sequence
                           and p.actor == e.actor and p.resource == e.resource
                           and 200 <= p.status < 300 for p in items):
                    out.append(("Successful step lacks observed successful prerequisite", (e.step,)))
        elif kind == "allowed_transition":
            need("from_step", "to_step")
            for a, b in zip(items, items[1:]):
                if a.step == c["from_step"] and b.step == c["to_step"] and a.actor == b.actor and a.resource == b.resource:
                    out.append(("Configured transition observed; review whether prohibited", (a.step, b.step)))
        elif kind in {"unique_success", "maximum_successes"}:
            need("step")
            limit = 1 if kind == "unique_success" else c.get("limit")
            if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
                raise ValidationError("Invalid success limit")
            buckets: dict[tuple[str, str, str], list[Event]] = {}
            for e in successes(c["step"]):
                buckets.setdefault((e.actor, e.resource, e.correlation), []).append(e)
            for bucket in buckets.values():
                if len(bucket) > limit:
                    out.append(("Observed successes exceed configured workflow limit", (bucket[0].step,)))
        elif kind == "fact_equals":
            need("step", "fact", "expected")
            for e in successes(c["step"]):
                if c["fact"] in e.facts and e.facts[c["fact"]] != c["expected"]:
                    out.append(("Observed fixture fact differs from expected value", (e.step,)))
        elif kind == "decimal_balance":
            need("step", "before", "delta", "after")
            for e in successes(c["step"]):
                if all(k in e.facts for k in (c["before"], c["delta"], c["after"])):
                    before, delta, after = (_decimal(e.facts[k]) for k in (c["before"], c["delta"], c["after"]))
                    if before + delta != after:
                        out.append(("Decimal balance invariant differs from observed fixture facts", (e.step,)))
        elif kind == "role_gate":
            need("step", "allowed_roles")
            allowed = c["allowed_roles"]
            if not isinstance(allowed, (list, tuple, set, frozenset)) or not all(isinstance(x, str) for x in allowed):
                raise ValidationError("Invalid allowed_roles")
            for e in successes(c["step"]):
                if e.role not in allowed:
                    out.append(("Success observed for role outside configured allowlist", (e.step,)))
        elif kind == "idempotency":
            need("step", "key_fact", "result_fact")
            seen: dict[tuple[str, str, str], Any] = {}
            for e in successes(c["step"]):
                if c["key_fact"] not in e.facts or c["result_fact"] not in e.facts:
                    continue
                key = (e.actor, e.resource, str(e.facts[c["key_fact"]]))
                result = e.facts[c["result_fact"]]
                if key in seen and seen[key] != result:
                    out.append(("Same idempotency key produced differing fixture results", (e.step,)))
                else:
                    seen[key] = result
        elif kind == "monotonic_fact":
            need("step", "fact", "direction")
            if c["direction"] not in {"nondecreasing", "nonincreasing"}:
                raise ValidationError("Invalid monotonic direction")
            previous: dict[tuple[str, str], Decimal] = {}
            for e in successes(c["step"]):
                if c["fact"] not in e.facts:
                    continue
                key = (e.actor, e.resource)
                value = _decimal(e.facts[c["fact"]])
                old = previous.get(key)
                if old is not None and ((c["direction"] == "nondecreasing" and value < old) or
                                        (c["direction"] == "nonincreasing" and value > old)):
                    out.append(("Observed value violates configured monotonic invariant", (e.step,)))
                previous[key] = value
        elif kind == "cross_actor_success":
            need("step")
            buckets: dict[str, set[str]] = {}
            for e in successes(c["step"]):
                if e.resource and e.actor:
                    buckets.setdefault(e.resource, set()).add(e.actor)
            for actors in buckets.values():
                if len(actors) > 1:
                    out.append(("Multiple actors succeeded on same fixture resource; review authorization", (c["step"],)))
        return out
