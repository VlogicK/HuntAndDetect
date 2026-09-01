import json
from pathlib import Path

import yaml


DETECTIONS_DIR = Path("Detections")
BUILD_DIR = Path("build/sentinel/rules")

API_VERSION = "2025-09-01"
RESOURCE_TYPE = "Microsoft.SecurityInsights/alertRules"


def load_yaml(path: Path) -> dict:
    """Load a detection YAML file."""

    with path.open("r", encoding="utf-8") as file:
        rule = yaml.safe_load(file)

    if not isinstance(rule, dict):
        raise ValueError(f"{path} does not contain a valid YAML object")

    return rule


def build_properties(rule: dict) -> dict:
    """Convert YAML fields into Sentinel Scheduled rule properties."""

    return {
        "displayName": rule["displayName"],
        "description": rule["description"],
        "severity": rule["severity"],
        "enabled": rule["enabled"],
        "query": rule["query"],
        "queryFrequency": rule["queryFrequency"],
        "queryPeriod": rule["queryPeriod"],
        "triggerOperator": rule["triggerOperator"],
        "triggerThreshold": rule["triggerThreshold"],
        "suppressionDuration": rule.get(
            "suppressionDuration",
            "PT5H",
        ),
        "suppressionEnabled": rule.get(
            "suppressionEnabled",
            False,
        ),
        "tactics": rule["tactics"],
        "techniques": rule["techniques"],
        "incidentConfiguration": rule["incidentConfiguration"],
        "eventGroupingSettings": rule["eventGroupingSettings"],
        "entityMappings": rule["entityMappings"],
    }


def build_resource(rule: dict) -> dict:
    """Build the Sentinel alertRules ARM resource."""

    return {
        "type": RESOURCE_TYPE,
        "apiVersion": API_VERSION,
        "name": rule["id"],
        "kind": rule["kind"],
        "properties": build_properties(rule),
    }


def build_arm_template(rule: dict) -> dict:
    """Wrap the Sentinel resource in an ARM deployment template."""

    return {
        "$schema": (
            "https://schema.management.azure.com/"
            "schemas/2019-04-01/deploymentTemplate.json#"
        ),
        "contentVersion": "1.0.0.0",
        "parameters": {},
        "resources": [
            build_resource(rule)
        ],
    }


def get_output_path(source_path: Path) -> Path:
    """
    Preserve the directory structure under Detections/.

    Detections/Persistence/test.yaml
        ->
    build/sentinel/rules/Persistence/test.json
    """

    relative_path = source_path.relative_to(DETECTIONS_DIR)

    return BUILD_DIR / relative_path.with_suffix(".json")


def convert_file(source_path: Path) -> Path:
    """Convert one YAML detection into Sentinel ARM JSON."""

    rule = load_yaml(source_path)
    arm_template = build_arm_template(rule)
    output_path = get_output_path(source_path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(
            arm_template,
            file,
            indent=2,
        )
        file.write("\n")

    return output_path


def main():
    """Convert every detection YAML file."""

    yaml_files = sorted(
        list(DETECTIONS_DIR.rglob("*.yaml"))
        + list(DETECTIONS_DIR.rglob("*.yml"))
    )

    if not yaml_files:
        print("No detection YAML files found.")
        return 1

    print(f"Found {len(yaml_files)} detection files.")

    failed = 0

    for yaml_file in yaml_files:
        try:
            output_file = convert_file(yaml_file)
            print(f"PASS  {yaml_file} -> {output_file}")

        except Exception as error:
            print(f"ERROR {yaml_file}: {error}")
            failed += 1

    if failed:
        print(f"\nFailed to convert {failed} detection(s).")
        return 1

    print(f"\nGenerated {len(yaml_files)} Sentinel rules.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
