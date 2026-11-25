from fastapi.testclient import TestClient

from rulesentry.main import app
from rulesentry.sigma_engine import map_attack_tags, test_rule as evaluate_rule, validate_rule

client = TestClient(app)

RULE = """title: Detect whoami
id: 11111111-1111-4111-8111-111111111111
status: experimental
description: Detect whoami execution
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: whoami.exe
  condition: selection
"""


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_validate_valid_rule():
    result = validate_rule(RULE)
    assert result.valid is True
    assert result.title == "Detect whoami"


def test_validate_invalid_yaml():
    result = validate_rule("title: [broken")
    assert result.valid is False
    assert result.diagnostics[0].code == "yaml.invalid"


def test_test_rule_matches_and_does_not_match():
    result = evaluate_rule(RULE, [
        {"Image": r"C:\Windows\System32\whoami.exe"},
        {"Image": r"C:\Windows\System32\notepad.exe"},
    ])
    assert result.supported is True
    assert result.matched_count == 1
    assert [item.matched for item in result.results] == [True, False]


def test_api_validate_and_test():
    response = client.post("/api/v1/rules/validate", json={"rule": RULE})
    assert response.status_code == 200
    assert response.json()["valid"] is True
    tested = client.post("/api/v1/rules/test", json={
        "rule": RULE, "events": [{"Image": "whoami.exe"}]
    })
    assert tested.status_code == 200
    assert tested.json()["matched_count"] == 1


def test_test_invalid_rule_is_not_evaluated():
    result = evaluate_rule("not: a valid sigma structure", [{"x": "y"}])
    assert result.supported is False
    assert result.results == []


def test_validate_rejects_non_string_status():
    malformed = RULE.replace("status: experimental", "status: [experimental]")
    result = validate_rule(malformed)
    assert result.valid is False
    assert any(item.code == "status.unknown" for item in result.diagnostics)


def test_condition_rejects_unknown_selection_pattern():
    malformed = RULE.replace("condition: selection", "condition: 1 of missing_*")
    result = evaluate_rule(malformed, [{"Image": "whoami.exe"}])
    assert result.supported is False
    assert result.results[0].matched is None



def test_attack_mapping_extracts_techniques_and_tactics():
    tagged_rule = RULE.replace(
        "status: experimental",
        "status: experimental\ntags:\n  - attack.execution\n  - attack.t1059\n  - attack.t1059.001\n",
    )
    result = map_attack_tags(tagged_rule)
    assert result.techniques == ["T1059", "T1059.001"]
    assert result.tactics == ["execution"]
    assert result.title == "Detect whoami"


def test_attack_mapping_warns_on_invalid_tags():
    tagged_rule = RULE.replace(
        "status: experimental",
        "status: experimental\ntags:\n  - attack.t1059.01\n",
    )
    result = map_attack_tags(tagged_rule)
    assert result.techniques == []
    assert any(item.code == "attack.tag.invalid" for item in result.diagnostics)


def test_attack_mapping_api_endpoint():
    tagged_rule = RULE.replace(
        "status: experimental",
        "status: experimental\ntags:\n  - attack.execution\n  - attack.t1059.001\n",
    )
    response = client.post("/api/v1/rules/attack-mapping", json={"rule": tagged_rule})
    assert response.status_code == 200
    assert response.json()["techniques"] == ["T1059.001"]
    assert response.json()["tactics"] == ["execution"]


def test_attack_coverage_aggregates_rules():
    first = RULE.replace(
        "status: experimental",
        "status: experimental\ntags:\n  - attack.execution\n  - attack.t1059\n",
    )
    second = RULE.replace(
        "title: Detect whoami",
        "title: Detect PowerShell",
    ).replace(
        "status: experimental",
        "status: experimental\ntags:\n  - attack.execution\n  - attack.t1059\n  - attack.t1059.001\n",
    )
    response = client.post("/api/v1/attack/coverage", json={"rules": [first, second]})
    assert response.status_code == 200
    payload = response.json()
    assert payload["rules_analyzed"] == 2
    assert payload["mapped_rule_count"] == 2
    assert payload["techniques"][0]["technique_id"] == "T1059"
    assert payload["techniques"][0]["rule_count"] == 2
    assert payload["tactics"][0]["tactic"] == "execution"
    assert payload["tactics"][0]["rule_count"] == 2



def test_attack_coverage_counts_distinct_rules_with_same_title():
    tagged_rule = RULE.replace(
        "status: experimental",
        "status: experimental\ntags:\n  - attack.t1059\n",
    )
    response = client.post("/api/v1/attack/coverage", json={"rules": [tagged_rule, tagged_rule]})
    assert response.status_code == 200
    payload = response.json()
    assert payload["techniques"][0]["rule_count"] == 2
    assert payload["techniques"][0]["rule_titles"] == ["Detect whoami", "Detect whoami"]
