import re
import sys
import uuid
from pathlib import Path

import yaml

VALID_KINDS = {"Scheduled"}
VALID_SEVERITIES = {"Informational", "Low", "Medium", "High"}
VALID_TRIGGER_OPERATORS = {"GreaterThan", "LessThan", "Equal", "NotEqual"}
VALID_TACTICS = {
    "Reconnaissance",
    "ResourceDevelopment",
    "InitialAccess",
    "Execution",
    "Persistence",
    "PrivilegeEscalation",
    "DefenseEvasion",
    "CredentialAccess",
    "Discovery",
    "LateralMovement",
    "Collection",
    "CommandAndControl",
    "Exfiltration",
    "Impact",
}

REQUIRED_FIELDS = {
    "id",
    "displayName",
    "description",
    "kind",
    "severity",
    "enabled",
    "query",
    "queryFrequency",
    "queryPeriod",
    "triggerOperator",
    "triggerThreshold",
    "tactics",
    "techniques",
    "subTechniques",
    "incidentConfiguration",
    "eventGroupingSettings",
    "entityMappings",
}

TECHNIQUE_RE = re.compile(r"^T\d{4}$")
SUBTECHNIQUE_RE = re.compile(r"^T\d{4}\.\d{3}$")
DURATION_RE = re.compile(r"^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$")


def _duration_seconds(value):
    if not isinstance(value, str):
        return None

    match = DURATION_RE.fullmatch(value)
    if not match or not any(match.groups()):
        return None

    hours, minutes, seconds = (int(part or 0) for part in match.groups())
    return hours * 3600 + minutes * 60 + seconds


def _non_empty_string(value):
    return isinstance(value, str) and bool(value.strip())


def validate_detection(rule):
    """Validate one Sentinel-aligned YAML detection.

    Returns two lists: hard errors and non-blocking quality warnings.
    """
    errors = []
    warnings = []

    if not isinstance(rule, dict):
        return ["YAML document must be an object/map"], warnings

    missing = sorted(REQUIRED_FIELDS - rule.keys())
    for field in missing:
        errors.append(f"Missing required field: {field}")

    if "id" in rule:
        try:
            uuid.UUID(str(rule["id"]))
        except (ValueError, AttributeError, TypeError):
            errors.append("id must be a valid UUID")

    if "displayName" in rule and not _non_empty_string(rule["displayName"]):
        errors.append("displayName must be a non-empty string")

    if "description" in rule:
        if not _non_empty_string(rule["description"]):
            errors.append("description must be a non-empty string")
        elif len(rule["description"].strip()) < 40:
            warnings.append("description is very short")

    if "kind" in rule and rule["kind"] not in VALID_KINDS:
        errors.append(
            f"Unsupported kind: {rule['kind']}. "
            f"Phase 1 supports: {', '.join(sorted(VALID_KINDS))}"
        )

    if "severity" in rule and rule["severity"] not in VALID_SEVERITIES:
        errors.append(f"Invalid severity: {rule['severity']}")

    if "enabled" in rule and not isinstance(rule["enabled"], bool):
        errors.append("enabled must be true or false")

    if "query" in rule and not _non_empty_string(rule["query"]):
        errors.append("query must be a non-empty string")

    frequency = _duration_seconds(rule.get("queryFrequency"))
    period = _duration_seconds(rule.get("queryPeriod"))

    if "queryFrequency" in rule and frequency is None:
        errors.append(
            "queryFrequency must be an ISO-8601 time duration such as PT5M or PT1H"
        )

    if "queryPeriod" in rule and period is None:
        errors.append(
            "queryPeriod must be an ISO-8601 time duration such as PT5M or PT1H"
        )

    if frequency is not None and period is not None and period < frequency:
        errors.append("queryPeriod cannot be shorter than queryFrequency")

    if (
        "triggerOperator" in rule
        and rule["triggerOperator"] not in VALID_TRIGGER_OPERATORS
    ):
        errors.append(f"Invalid triggerOperator: {rule['triggerOperator']}")

    if "triggerThreshold" in rule:
        threshold = rule["triggerThreshold"]
        if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 0:
            errors.append("triggerThreshold must be a non-negative integer")

    tactics = rule.get("tactics")
    if "tactics" in rule:
        if not isinstance(tactics, list) or not tactics:
            errors.append("tactics must be a non-empty list")
        else:
            for tactic in tactics:
                if tactic not in VALID_TACTICS:
                    errors.append(f"Invalid tactic: {tactic}")

    techniques = rule.get("techniques")
    if "techniques" in rule:
        if not isinstance(techniques, list):
            errors.append("techniques must be a list")
        else:
            for technique in techniques:
                if not isinstance(technique, str) or not TECHNIQUE_RE.fullmatch(technique):
                    errors.append(f"Invalid technique format: {technique}")
            if not techniques:
                warnings.append("No MITRE ATT&CK techniques defined")

    subtechniques = rule.get("subTechniques")
    if "subTechniques" in rule:
        if not isinstance(subtechniques, list):
            errors.append("subTechniques must be a list")
        else:
            for technique in subtechniques:
                if not isinstance(technique, str) or not SUBTECHNIQUE_RE.fullmatch(technique):
                    errors.append(f"Invalid sub-technique format: {technique}")

    incident_config = rule.get("incidentConfiguration")
    if "incidentConfiguration" in rule:
        if not isinstance(incident_config, dict):
            errors.append("incidentConfiguration must be an object/map")
        elif not isinstance(incident_config.get("createIncident"), bool):
            errors.append("incidentConfiguration.createIncident must be true or false")

    event_grouping = rule.get("eventGroupingSettings")
    if "eventGroupingSettings" in rule:
        if not isinstance(event_grouping, dict):
            errors.append("eventGroupingSettings must be an object/map")
        elif event_grouping.get("aggregationKind") not in {
            "AlertPerResult",
            "SingleAlert",
        }:
            errors.append(
                "eventGroupingSettings.aggregationKind must be "
                "AlertPerResult or SingleAlert"
            )

    entity_mappings = rule.get("entityMappings")
    if "entityMappings" in rule:
        if entity_mappings is None:
            warnings.append("No entity mappings defined")
        elif not isinstance(entity_mappings, list):
            errors.append("entityMappings must be a list")
        elif not entity_mappings:
            warnings.append("No entity mappings defined")

    return errors, warnings


def load_detection(path):
    try:
        with path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle), None
    except yaml.YAMLError as exc:
        return None, f"Invalid YAML: {exc}"
    except OSError as exc:
        return None, f"Unable to read file: {exc}"


def validate_repository(root=Path("Detections")):
    results = []
    seen_ids = {}

    paths = sorted([*root.rglob("*.yaml"), *root.rglob("*.yml")])

    for path in paths:
        rule, load_error = load_detection(path)
        if load_error:
            results.append((path, [load_error], []))
            continue

        errors, warnings = validate_detection(rule)

        if isinstance(rule, dict) and rule.get("id"):
            rule_id = str(rule["id"])
            if rule_id in seen_ids:
                errors.append(f"Duplicate id also used by {seen_ids[rule_id]}")
            else:
                seen_ids[rule_id] = path

        results.append((path, errors, warnings))

    return results


def main():
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("Detections")

    if not root.exists():
        print(f"ERROR: detection directory not found: {root}")
        return 1

    results = validate_repository(root)

    if not results:
        print(f"ERROR: no YAML detections found under {root}")
        return 1

    total_errors = 0
    total_warnings = 0

    for path, errors, warnings in results:
        print(f"\n{path}")

        if errors:
            for error in errors:
                print(f"  ERROR: {error}")
        else:
            print("  PASS")

        for warning in warnings:
            print(f"  WARNING: {warning}")

        total_errors += len(errors)
        total_warnings += len(warnings)

    print(
        f"\nValidated {len(results)} detection(s): "
        f"{total_errors} error(s), {total_warnings} warning(s)"
    )

    if total_errors:
        print("Validation FAILED")
        return 1

    print("Validation PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
