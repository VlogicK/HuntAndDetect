import importlib.util
import json
from pathlib import Path

import pytest


DEPLOY_PATH = Path(__file__).parents[1] / "tools" / "deploy.py"
spec = importlib.util.spec_from_file_location("sentinel_deploy", DEPLOY_PATH)
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)


def built_rule(rule_id="ca433e75-e313-59f7-899b-64e12a93f8eb"):
    return {
        "resources": [
            {
                "type": "Microsoft.SecurityInsights/alertRules",
                "apiVersion": "2025-09-01",
                "name": rule_id,
                "kind": "Scheduled",
                "properties": {
                    "displayName": "Example Sentinel Detection",
                    "severity": "Medium",
                    "enabled": True,
                    "query": "DeviceProcessEvents | take 1",
                    "queryFrequency": "PT1H",
                    "queryPeriod": "PT1H",
                    "triggerOperator": "GreaterThan",
                    "triggerThreshold": 0,
                    "suppressionDuration": "PT5H",
                    "suppressionEnabled": False,
                    "tactics": ["Execution"],
                    "techniques": ["T1059"],
                    "incidentConfiguration": {"createIncident": True},
                    "eventGroupingSettings": {
                        "aggregationKind": "AlertPerResult"
                    },
                },
            }
        ]
    }


def write_rule(path: Path, rule_id=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = built_rule(rule_id) if rule_id else built_rule()
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_find_rule_files_accepts_single_json_file(tmp_path):
    rule = tmp_path / "rule.json"
    write_rule(rule)

    assert deploy.find_rule_files(rule) == [rule]


def test_find_rule_files_recurses_and_sorts(tmp_path):
    first = tmp_path / "Defense Evasion" / "a.json"
    second = tmp_path / "Persistence" / "b.json"
    write_rule(second)
    write_rule(first)

    assert deploy.find_rule_files(tmp_path) == [first, second]


def test_find_rule_files_rejects_empty_directory(tmp_path):
    with pytest.raises(ValueError, match="No generated Sentinel rule JSON files"):
        deploy.find_rule_files(tmp_path)


def test_load_built_rule_returns_single_resource(tmp_path):
    rule_path = tmp_path / "rule.json"
    write_rule(rule_path)

    resource = deploy.load_built_rule(rule_path)

    assert resource["name"] == "ca433e75-e313-59f7-899b-64e12a93f8eb"
    assert resource["kind"] == "Scheduled"


def test_build_rule_url_uses_expected_sentinel_endpoint():
    url = deploy.build_rule_url(
        "sub id",
        "sentinel lab",
        "workspace/name",
        "rule-id",
    )

    assert url == (
        "https://management.azure.com/subscriptions/sub%20id"
        "/resourceGroups/sentinel%20lab"
        "/providers/Microsoft.OperationalInsights"
        "/workspaces/workspace%2Fname"
        "/providers/Microsoft.SecurityInsights"
        "/alertRules/rule-id?api-version=2025-09-01"
    )


def test_build_request_body_only_sends_kind_and_properties():
    resource = built_rule()["resources"][0]

    body = deploy.build_request_body(resource)

    assert set(body) == {"kind", "properties"}
    assert body["kind"] == "Scheduled"
    assert body["properties"]["enabled"] is True


def test_dry_run_does_not_request_access_token(monkeypatch, tmp_path, capsys):
    rules_dir = tmp_path / "rules"
    write_rule(rules_dir / "one.json")
    write_rule(
        rules_dir / "nested" / "two.json",
        "082c4eef-9ad3-5cb6-8968-2a330384a581",
    )

    def fail_if_called():
        raise AssertionError("get_access_token should not run during dry-run")

    monkeypatch.setattr(deploy, "get_access_token", fail_if_called)
    monkeypatch.setattr(
        deploy,
        "parse_args",
        lambda: type(
            "Args",
            (),
            {
                "rules": rules_dir,
                "subscription_id": "subscription",
                "resource_group": "resource-group",
                "workspace": "workspace",
                "apply": False,
            },
        )(),
    )

    assert deploy.main() == 0
    output = capsys.readouterr().out
    assert "Found 2 generated Sentinel rule(s)." in output
    assert output.count("DRY RUN - no changes will be made") == 2


def test_apply_deploys_every_rule_with_one_token(monkeypatch, tmp_path, capsys):
    rules_dir = tmp_path / "rules"
    write_rule(rules_dir / "one.json")
    write_rule(
        rules_dir / "nested" / "two.json",
        "082c4eef-9ad3-5cb6-8968-2a330384a581",
    )

    token_calls = []
    deployed = []

    def fake_token():
        token_calls.append(True)
        return "token"

    def fake_deploy(resource, subscription_id, resource_group, workspace, token):
        deployed.append(resource["name"])
        return {"name": resource["name"]}

    monkeypatch.setattr(deploy, "get_access_token", fake_token)
    monkeypatch.setattr(deploy, "deploy_rule", fake_deploy)
    monkeypatch.setattr(
        deploy,
        "parse_args",
        lambda: type(
            "Args",
            (),
            {
                "rules": rules_dir,
                "subscription_id": "subscription",
                "resource_group": "resource-group",
                "workspace": "workspace",
                "apply": True,
            },
        )(),
    )

    assert deploy.main() == 0
    assert len(token_calls) == 1
    assert deployed == [
        "082c4eef-9ad3-5cb6-8968-2a330384a581",
        "ca433e75-e313-59f7-899b-64e12a93f8eb",
    ]
    assert "Deployed 2 Sentinel rule(s)." in capsys.readouterr().out


def test_apply_continues_after_one_rule_fails(monkeypatch, tmp_path, capsys):
    rules_dir = tmp_path / "rules"
    first_id = "082c4eef-9ad3-5cb6-8968-2a330384a581"
    second_id = "ca433e75-e313-59f7-899b-64e12a93f8eb"
    write_rule(rules_dir / "a.json", first_id)
    write_rule(rules_dir / "b.json", second_id)

    attempted = []

    monkeypatch.setattr(deploy, "get_access_token", lambda: "token")

    def fake_deploy(resource, subscription_id, resource_group, workspace, token):
        attempted.append(resource["name"])
        if resource["name"] == first_id:
            raise RuntimeError("example deployment failure")
        return {"name": resource["name"]}

    monkeypatch.setattr(deploy, "deploy_rule", fake_deploy)
    monkeypatch.setattr(
        deploy,
        "parse_args",
        lambda: type(
            "Args",
            (),
            {
                "rules": rules_dir,
                "subscription_id": "subscription",
                "resource_group": "resource-group",
                "workspace": "workspace",
                "apply": True,
            },
        )(),
    )

    assert deploy.main() == 1
    assert attempted == [first_id, second_id]
    captured = capsys.readouterr()
    assert "PASS" in captured.out
    assert "Failed to deploy 1 of 2 rule(s)." in captured.err
