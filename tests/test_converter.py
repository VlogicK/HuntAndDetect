import importlib.util
import json
from pathlib import Path

import pytest
import yaml


CONVERTER_PATH = Path(__file__).parents[1] / "tools" / "convert.py"
spec = importlib.util.spec_from_file_location("sentinel_converter", CONVERTER_PATH)
converter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(converter)


def valid_rule():
    return {
        "id": "ca433e75-e313-59f7-899b-64e12a93f8eb",
        "displayName": "Example Sentinel Detection",
        "description": "Detects an example security event for converter unit testing.",
        "kind": "Scheduled",
        "severity": "Medium",
        "enabled": True,
        "author": "VaasudevKala",
        "query": "DeviceProcessEvents\n| where FileName =~ 'example.exe'",
        "queryFrequency": "PT1H",
        "queryPeriod": "PT1H",
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 0,
        "suppressionDuration": "PT5H",
        "suppressionEnabled": False,
        "tactics": ["Execution"],
        "techniques": ["T1059"],
        "subTechniques": ["T1059.001"],
        "incidentConfiguration": {"createIncident": True},
        "eventGroupingSettings": {"aggregationKind": "AlertPerResult"},
        "entityMappings": [],
    }


def test_build_resource_preserves_rule_identity_and_kind():
    resource = converter.build_resource(valid_rule())

    assert resource["name"] == "ca433e75-e313-59f7-899b-64e12a93f8eb"
    assert resource["kind"] == "Scheduled"
    assert resource["type"] == "Microsoft.SecurityInsights/alertRules"
    assert resource["apiVersion"] == "2025-09-01"


def test_build_properties_maps_detection_fields():
    rule = valid_rule()
    properties = converter.build_properties(rule)

    assert properties["displayName"] == rule["displayName"]
    assert properties["query"] == rule["query"]
    assert properties["severity"] == "Medium"
    assert properties["queryFrequency"] == "PT1H"
    assert properties["queryPeriod"] == "PT1H"
    assert properties["tactics"] == ["Execution"]
    assert properties["techniques"] == ["T1059"]


def test_empty_entity_mappings_are_omitted():
    properties = converter.build_properties(valid_rule())

    assert "entityMappings" not in properties


def test_non_empty_entity_mappings_are_preserved():
    rule = valid_rule()
    rule["entityMappings"] = [
        {
            "entityType": "Host",
            "fieldMappings": [
                {
                    "identifier": "HostName",
                    "columnName": "DeviceName",
                }
            ],
        }
    ]

    properties = converter.build_properties(rule)

    assert properties["entityMappings"] == rule["entityMappings"]


def test_repo_only_metadata_is_not_emitted_to_sentinel_properties():
    properties = converter.build_properties(valid_rule())

    assert "author" not in properties
    assert "subTechniques" not in properties


def test_get_output_path_preserves_detection_directory(monkeypatch, tmp_path):
    detections_dir = tmp_path / "Detections"
    build_dir = tmp_path / "build" / "sentinel" / "rules"

    monkeypatch.setattr(converter, "DETECTIONS_DIR", detections_dir)
    monkeypatch.setattr(converter, "BUILD_DIR", build_dir)

    source = detections_dir / "Defense Evasion" / "example.yml"

    assert converter.get_output_path(source) == (
        build_dir / "Defense Evasion" / "example.json"
    )


def test_convert_file_writes_valid_arm_json(monkeypatch, tmp_path):
    detections_dir = tmp_path / "Detections"
    build_dir = tmp_path / "build" / "sentinel" / "rules"
    source = detections_dir / "Persistence" / "example.yaml"

    source.parent.mkdir(parents=True)
    source.write_text(yaml.safe_dump(valid_rule()), encoding="utf-8")

    monkeypatch.setattr(converter, "DETECTIONS_DIR", detections_dir)
    monkeypatch.setattr(converter, "BUILD_DIR", build_dir)

    output = converter.convert_file(source)

    assert output == build_dir / "Persistence" / "example.json"
    assert output.exists()

    template = json.loads(output.read_text(encoding="utf-8"))
    assert template["contentVersion"] == "1.0.0.0"
    assert len(template["resources"]) == 1
    assert template["resources"][0]["name"] == valid_rule()["id"]
    assert template["resources"][0]["properties"]["query"] == valid_rule()["query"]


def test_load_yaml_rejects_non_object(tmp_path):
    source = tmp_path / "invalid.yaml"
    source.write_text("- one\n- two\n", encoding="utf-8")

    with pytest.raises(ValueError, match="does not contain a valid YAML object"):
        converter.load_yaml(source)
