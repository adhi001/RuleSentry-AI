"""Small, transparent Sigma-style validator and event matcher.

This intentionally supports a documented subset, not the complete Sigma specification.
"""
from __future__ import annotations

import ast
import re
from typing import Any

import yaml

from .models import (
    AttackCoverageResponse, AttackMappingResponse, AttackTacticCoverage,
    AttackTechniqueCoverage, Diagnostic, EventResult, TestResponse, ValidateResponse,
)

_REQUIRED = ("title", "id", "status", "description", "logsource", "detection")
_ALLOWED_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}
_MODIFIERS = {"contains", "startswith", "endswith", "re", "all"}
_ATTACK_TECHNIQUE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_ATTACK_TACTIC = re.compile(r"^attack\.([a-z][a-z0-9_-]*)$", re.IGNORECASE)


class RuleError(ValueError):
    """Raised when input cannot be interpreted by this subset engine."""


def parse_rule(source: str) -> dict[str, Any]:
    try:
        value = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        raise RuleError(f"Invalid YAML: {exc}") from exc
    if not isinstance(value, dict):
        raise RuleError("A rule must be a YAML mapping.")
    return value


def validate_rule(source: str) -> ValidateResponse:
    diagnostics: list[Diagnostic] = []
    try:
        rule = parse_rule(source)
    except RuleError as exc:
        return ValidateResponse(valid=False, diagnostics=[
            Diagnostic(severity="error", code="yaml.invalid", message=str(exc))
        ])

    for field in _REQUIRED:
        if field not in rule:
            diagnostics.append(Diagnostic(severity="error", code="field.missing",
                                          message=f"Required field '{field}' is missing."))
    if not isinstance(rule.get("title"), str) or not rule.get("title", "").strip():
        diagnostics.append(Diagnostic(severity="error", code="title.invalid",
                                      message="title must be a non-empty string."))
    if "status" in rule and (not isinstance(rule["status"], str) or rule["status"] not in _ALLOWED_STATUS):
        diagnostics.append(Diagnostic(severity="warning", code="status.unknown",
                                      message="status is not a commonly used Sigma status."))
    if "logsource" in rule and not isinstance(rule["logsource"], dict):
        diagnostics.append(Diagnostic(severity="error", code="logsource.invalid",
                                      message="logsource must be a mapping."))
    detection = rule.get("detection")
    if not isinstance(detection, dict):
        diagnostics.append(Diagnostic(severity="error", code="detection.invalid",
                                      message="detection must be a mapping."))
    else:
        if not isinstance(detection.get("condition"), str) or not detection["condition"].strip():
            diagnostics.append(Diagnostic(severity="error", code="condition.missing",
                                          message="detection.condition must be a non-empty string."))
        selections = [key for key in detection if key != "condition"]
        if not selections:
            diagnostics.append(Diagnostic(severity="error", code="selection.missing",
                                          message="At least one selection is required."))
        for name in selections:
            if not isinstance(name, str):
                diagnostics.append(Diagnostic(severity="error", code="selection.name.invalid",
                                              message="Selection names must be strings."))
            if not isinstance(detection[name], (dict, list)):
                diagnostics.append(Diagnostic(severity="error", code="selection.invalid",
                                              message=f"Selection '{name}' must be a mapping or list."))
    return ValidateResponse(
        valid=not any(item.severity == "error" for item in diagnostics),
        title=rule.get("title") if isinstance(rule.get("title"), str) else None,
        rule_id=rule.get("id") if isinstance(rule.get("id"), str) else None,
        diagnostics=diagnostics,
    )


def map_attack_tags(source: str) -> AttackMappingResponse:
    """Extract ATT&CK technique and tactic identifiers from Sigma attack.* tags."""
    try:
        rule = parse_rule(source)
    except RuleError as exc:
        return AttackMappingResponse(diagnostics=[
            Diagnostic(severity="error", code="yaml.invalid", message=str(exc))
        ])

    diagnostics: list[Diagnostic] = []
    tags = rule.get("tags", [])
    techniques: set[str] = set()
    tactics: set[str] = set()
    if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
        diagnostics.append(Diagnostic(
            severity="warning", code="attack.tags.invalid",
            message="Sigma tags must be a list of strings; ATT&CK mapping was skipped for invalid tags.",
        ))
        tags = []

    for tag in tags:
        normalized = tag.strip().lower()
        if not normalized.startswith("attack."):
            continue
        technique_match = _ATTACK_TECHNIQUE.fullmatch(normalized)
        if technique_match:
            techniques.add(technique_match.group(1).upper())
            continue
        tactic_match = _ATTACK_TACTIC.fullmatch(normalized)
        if tactic_match:
            tactics.add(tactic_match.group(1).replace("-", "_"))
            continue
        diagnostics.append(Diagnostic(
            severity="warning", code="attack.tag.invalid",
            message=f"Unrecognized ATT&CK tag '{tag}'. Expected attack.t####, attack.t####.###, or an attack tactic slug.",
        ))

    return AttackMappingResponse(
        title=rule.get("title") if isinstance(rule.get("title"), str) else None,
        rule_id=rule.get("id") if isinstance(rule.get("id"), str) else None,
        techniques=sorted(techniques),
        tactics=sorted(tactics),
        diagnostics=diagnostics,
    )


def attack_coverage(sources: list[str]) -> AttackCoverageResponse:
    """Aggregate ATT&CK tag coverage across a caller-supplied rule collection."""
    technique_rules: dict[str, set[str]] = {}
    tactic_rules: dict[str, set[str]] = {}
    diagnostics: list[Diagnostic] = []
    mapped_rule_ids: set[int] = set()

    for index, source in enumerate(sources, start=1):
        mapping = map_attack_tags(source)
        title = mapping.title or f"Rule {index}"
        if mapping.techniques or mapping.tactics:
            mapped_rule_ids.add(index)
        for technique in mapping.techniques:
            technique_rules.setdefault(technique, set()).add(title)
        for tactic in mapping.tactics:
            tactic_rules.setdefault(tactic, set()).add(title)
        for diagnostic in mapping.diagnostics:
            diagnostics.append(Diagnostic(
                severity=diagnostic.severity,
                code=diagnostic.code,
                message=f"Rule {index} ({title}): {diagnostic.message}",
            ))

    techniques = [
        AttackTechniqueCoverage(
            technique_id=identifier,
            rule_count=len(titles),
            rule_titles=sorted(titles),
        )
        for identifier, titles in sorted(technique_rules.items())
    ]
    tactics = [
        AttackTacticCoverage(
            tactic=tactic,
            rule_count=len(titles),
            rule_titles=sorted(titles),
        )
        for tactic, titles in sorted(tactic_rules.items())
    ]
    return AttackCoverageResponse(
        rules_analyzed=len(sources),
        mapped_rule_count=len(mapped_rule_ids),
        techniques=techniques,
        tactics=tactics,
        diagnostics=diagnostics,
    )


def _field_match(event: dict[str, Any], expression: str, expected: Any) -> bool:
    parts = expression.split("|")
    field, modifiers = parts[0], parts[1:]
    if any(modifier not in _MODIFIERS for modifier in modifiers):
        raise RuleError(f"Unsupported modifier in '{expression}'.")
    if field not in event:
        return False
    actual = event[field]
    candidates = expected if isinstance(expected, list) else [expected]

    def one(value: Any) -> bool:
        if not isinstance(actual, (str, int, float, bool)) or not isinstance(value, (str, int, float, bool)):
            return actual == value
        left, right = str(actual).lower(), str(value).lower()
        if "re" in modifiers:
            try:
                return re.search(str(value), str(actual), re.IGNORECASE) is not None
            except re.error as exc:
                raise RuleError(f"Invalid regular expression: {exc}") from exc
        if "contains" in modifiers:
            return right in left
        if "startswith" in modifiers:
            return left.startswith(right)
        if "endswith" in modifiers:
            return left.endswith(right)
        return left == right

    matches = [one(value) for value in candidates]
    return all(matches) if "all" in modifiers else any(matches)


def _selection_match(event: dict[str, Any], selection: Any) -> bool:
    if isinstance(selection, list):
        return any(_selection_match(event, item) for item in selection)
    if not isinstance(selection, dict):
        raise RuleError("Selection must be a mapping or list.")
    return all(_field_match(event, key, value) for key, value in selection.items())


def _expand_group(pattern: str, names: list[str], all_required: bool) -> str:
    regex = "^" + re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".") + "$"
    matched = [name for name in names if re.match(regex, name, re.IGNORECASE)]
    if not matched:
        raise RuleError(f"Selection pattern '{pattern}' matched no selections.")
    joiner = " and " if all_required else " or "
    return "(" + joiner.join(matched) + ")"


def _condition_result(event: dict[str, Any], detection: dict[str, Any]) -> bool:
    names = [name for name in detection if name != "condition"]
    values = {name: _selection_match(event, detection[name]) for name in names}
    condition = str(detection["condition"]).strip()
    condition = re.sub(
        r"\b(1|all)\s+of\s+them\b",
        lambda match: "(" + (" or " if match.group(1).lower() == "1" else " and ").join(names) + ")",
        condition, flags=re.IGNORECASE,
    )
    condition = re.sub(
        r"\b(1|all)\s+of\s+([A-Za-z0-9_*?]+)\b",
        lambda match: _expand_group(match.group(2), names, match.group(1).lower() == "all"),
        condition, flags=re.IGNORECASE,
    )
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*|\(|\)|\bAND\b|\bOR\b|\bNOT\b", condition, re.I)
    if "".join(tokens).lower() != re.sub(r"\s+", "", condition).lower():
        raise RuleError("Condition uses syntax outside the supported subset.")
    expression = condition
    for name in sorted(names, key=len, reverse=True):
        expression = re.sub(rf"\b{re.escape(name)}\b", str(values[name]), expression)
    expression = re.sub(r"\bAND\b", " and ", expression, flags=re.I)
    expression = re.sub(r"\bOR\b", " or ", expression, flags=re.I)
    expression = re.sub(r"\bNOT\b", " not ", expression, flags=re.I)
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError as exc:
        raise RuleError("Could not parse condition; use selection names with and/or/not.") from exc

    def evaluate(node: ast.AST) -> bool:
        if isinstance(node, ast.Expression):
            return evaluate(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, bool):
            return node.value
        if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
            checks = [evaluate(item) for item in node.values]
            return all(checks) if isinstance(node.op, ast.And) else any(checks)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not evaluate(node.operand)
        raise RuleError("Unsupported condition expression.")
    return evaluate(tree)


def test_rule(source: str, events: list[dict[str, Any]]) -> TestResponse:
    validation = validate_rule(source)
    if not validation.valid:
        return TestResponse(supported=False, matched_count=0, total_events=len(events),
                            results=[], diagnostics=validation.diagnostics)
    detection = parse_rule(source)["detection"]
    results: list[EventResult] = []
    for index, event in enumerate(events):
        try:
            matched = _condition_result(event, detection)
            results.append(EventResult(index=index, matched=matched,
                                       reason="Condition matched." if matched else "Condition did not match."))
        except RuleError as exc:
            results.append(EventResult(index=index, matched=None, reason=str(exc)))
    supported = all(item.matched is not None for item in results)
    diagnostics = [] if supported else [Diagnostic(
        severity="warning", code="test.unsupported",
        message="One or more events could not be evaluated by the supported syntax subset."
    )]
    return TestResponse(supported=supported,
                        matched_count=sum(item.matched is True for item in results),
                        total_events=len(events), results=results, diagnostics=diagnostics)
