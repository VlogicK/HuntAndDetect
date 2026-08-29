import copy
import importlib.util
from pathlib import Path

VALIDATOR_PATH = Path(__file__).parents[1] / "tools" / "validate.py"
spec = importlib.util.spec_from_file_location("detection_validator", VALIDATOR_PATH)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


def valid_rule():
    return {
        "id": "ca433e75-e313-59f7-899b-64e12a93f8eb",
        "displayName": "Example Sentinel Detection",
        "description": "Detects an example security event for validator unit testing.",
        "kind": "Scheduled",
        "severity": "Medium",
        "enabled": True,
        "query": "DeviceProcessEvents\n| where FileName =~ 'example.exe'",
        "queryFrequency": "PT1H",
        "queryPeriod": "PT1H",
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 0,
        "tactics": ["Execution"],
        "techniques": ["T1059"],
        "subTechniques": [],
        "incidentConfiguration": {"createIncident": True},
        "eventGroupingSettings": {"aggregationKind": "AlertPerResult"},
        "entityMappings": [],
    }


def test_valid_rule_has_no_errors():
    errors, warnings = validator.validate_detection(valid_rule())

    assert errors == []
    assert "No entity mappings defined" in warnings


def test_missing_query_is_an_error():
    rule = valid_rule()
    del rule["query"]

    errors, _ = validator.validate_detection(rule)

    assert "Missing required field: query" in errors


def test_invalid_severity_is_an_error():
    rule = valid_rule()
    rule["severity"] = "Critical"

    errors, _ = validator.validate_detection(rule)

    assert "Invalid severity: Critical" in errors


def test_invalid_uuid_is_an_error():
    rule = valid_rule()
    rule["id"] = "DET-EXEC-001"

    errors, _ = validator.validate_detection(rule)

    assert "id must be a valid UUID" in errors


def test_query_period_cannot_be_shorter_than_frequency():
    rule = valid_rule()
    rule["queryFrequency"] = "PT1H"
    rule["queryPeriod"] = "PT5M"

    errors, _ = validator.validate_detection(rule)

    assert "queryPeriod cannot be shorter than queryFrequency" in errors


def test_bad_mitre_format_is_an_error():
    rule = valid_rule()
    rule["techniques"] = ["T1059.001"]

    errors, _ = validator.validate_detection(rule)

    assert "Invalid technique format: T1059.001" in errors


def test_missing_techniques_is_only_a_warning():
    rule = copy.deepcopy(valid_rule())
    rule["techniques"] = []

    errors, warnings = validator.validate_detection(rule)

    assert errors == []
    assert "No MITRE ATT&CK techniques defined" in warnings
