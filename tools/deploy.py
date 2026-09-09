import argparse
import json
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


API_VERSION = "2025-09-01"
MANAGEMENT_SCOPE = "https://management.azure.com/"


def get_access_token() -> str:
    """Get an Azure management token from the current Azure CLI login."""

    command = [
        "az",
        "account",
        "get-access-token",
        "--resource",
        MANAGEMENT_SCOPE,
        "--query",
        "accessToken",
        "--output",
        "tsv",
    ]

    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as error:
        raise RuntimeError(
            "Azure CLI is not installed or is not available on PATH"
        ) from error
    except subprocess.CalledProcessError as error:
        message = error.stderr.strip() or error.stdout.strip()
        raise RuntimeError(
            f"Unable to get an Azure access token: {message}"
        ) from error

    token = result.stdout.strip()

    if not token:
        raise RuntimeError("Azure CLI returned an empty access token")

    return token


def load_built_rule(path: Path) -> dict:
    """Load one generated ARM template and return its Sentinel rule resource."""

    with path.open("r", encoding="utf-8") as file:
        template = json.load(file)

    resources = template.get("resources")

    if not isinstance(resources, list) or len(resources) != 1:
        raise ValueError(
            f"{path} must contain exactly one generated Sentinel rule resource"
        )

    resource = resources[0]

    if not isinstance(resource, dict):
        raise ValueError(f"{path} contains an invalid resource")

    required = {"name", "kind", "properties"}
    missing = sorted(required - resource.keys())

    if missing:
        raise ValueError(
            f"{path} is missing resource field(s): {', '.join(missing)}"
        )

    return resource


def build_rule_url(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    rule_id: str,
) -> str:
    """Build the Microsoft Sentinel analytics-rule REST endpoint."""

    parts = {
        "subscription": urllib.parse.quote(subscription_id, safe=""),
        "resource_group": urllib.parse.quote(resource_group, safe=""),
        "workspace": urllib.parse.quote(workspace, safe=""),
        "rule_id": urllib.parse.quote(rule_id, safe=""),
    }

    return (
        f"https://management.azure.com/subscriptions/{parts['subscription']}"
        f"/resourceGroups/{parts['resource_group']}"
        "/providers/Microsoft.OperationalInsights"
        f"/workspaces/{parts['workspace']}"
        "/providers/Microsoft.SecurityInsights"
        f"/alertRules/{parts['rule_id']}"
        f"?api-version={API_VERSION}"
    )


def build_request_body(resource: dict) -> dict:
    """Build the Sentinel REST request body from a generated resource."""

    return {
        "kind": resource["kind"],
        "properties": resource["properties"],
    }


def deploy_rule(
    resource: dict,
    subscription_id: str,
    resource_group: str,
    workspace: str,
    access_token: str,
) -> dict:
    """Create or update one Microsoft Sentinel analytics rule."""

    url = build_rule_url(
        subscription_id,
        resource_group,
        workspace,
        resource["name"],
    )
    body = build_request_body(resource)

    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
        method="PUT",
    )

    try:
        with urllib.request.urlopen(request) as response:
            payload = response.read().decode("utf-8")
            return json.loads(payload) if payload else {}
    except urllib.error.HTTPError as error:
        response_body = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"Sentinel API returned HTTP {error.code}: {response_body}"
        ) from error


def print_dry_run(
    resource: dict,
    subscription_id: str,
    resource_group: str,
    workspace: str,
) -> None:
    """Print the request that would be sent without making any Azure change."""

    url = build_rule_url(
        subscription_id,
        resource_group,
        workspace,
        resource["name"],
    )
    body = build_request_body(resource)

    print("DRY RUN - no changes will be made")
    print(f"Method: PUT")
    print(f"URL: {url}")
    print("Body:")
    print(json.dumps(body, indent=2))


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Preview or deploy a generated Microsoft Sentinel analytics rule. "
            "Dry-run is the default; pass --apply to make the Azure change."
        )
    )
    parser.add_argument("rule", type=Path, help="Path to generated rule JSON")
    parser.add_argument("--subscription-id", required=True)
    parser.add_argument("--resource-group", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually create or update the Sentinel rule",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    try:
        resource = load_built_rule(args.rule)

        if not args.apply:
            print_dry_run(
                resource,
                args.subscription_id,
                args.resource_group,
                args.workspace,
            )
            return 0

        token = get_access_token()
        result = deploy_rule(
            resource,
            args.subscription_id,
            args.resource_group,
            args.workspace,
            token,
        )
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(
        "Deployed Sentinel rule: "
        f"{result.get('name', resource['name'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
