import argparse
import json
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


API_VERSION = "2025-09-01"
MANAGEMENT_SCOPE = "https://management.azure.com/"
DEFAULT_RULES_DIR = Path("build/sentinel/rules")


def find_azure_cli() -> str:
    """Find the Azure CLI executable across Windows and Unix-like systems."""

    executable = shutil.which("az") or shutil.which("az.cmd")

    if not executable:
        raise RuntimeError(
            "Azure CLI is not installed or is not available on PATH"
        )

    return executable


def get_access_token() -> str:
    """Get an Azure management token from the current Azure CLI login."""

    command = [
        find_azure_cli(),
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
    except subprocess.CalledProcessError as error:
        message = error.stderr.strip() or error.stdout.strip()
        raise RuntimeError(
            f"Unable to get an Azure access token: {message}"
        ) from error

    token = result.stdout.strip()

    if not token:
        raise RuntimeError("Azure CLI returned an empty access token")

    return token


def find_rule_files(path: Path) -> list[Path]:
    """Return generated Sentinel rule JSON files from a file or directory."""

    if path.is_file():
        if path.suffix.lower() != ".json":
            raise ValueError(f"{path} is not a JSON rule file")
        return [path]

    if not path.exists():
        raise ValueError(f"{path} does not exist")

    if not path.is_dir():
        raise ValueError(f"{path} is not a file or directory")

    rule_files = sorted(path.rglob("*.json"))

    if not rule_files:
        raise ValueError(f"No generated Sentinel rule JSON files found in {path}")

    return rule_files


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
    print("Method: PUT")
    print(f"URL: {url}")
    print("Body:")
    print(json.dumps(body, indent=2))


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Preview or deploy generated Microsoft Sentinel analytics rules. "
            "Dry-run is the default; pass --apply to make Azure changes."
        )
    )
    parser.add_argument(
        "rules",
        nargs="?",
        type=Path,
        default=DEFAULT_RULES_DIR,
        help=(
            "Generated rule JSON file or directory. "
            "Defaults to build/sentinel/rules"
        ),
    )
    parser.add_argument("--subscription-id", required=True)
    parser.add_argument("--resource-group", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually create or update the Sentinel rules",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    try:
        rule_files = find_rule_files(args.rules)
        resources = [(path, load_built_rule(path)) for path in rule_files]

        if not args.apply:
            print(f"Found {len(resources)} generated Sentinel rule(s).")
            for index, (path, resource) in enumerate(resources, start=1):
                print(f"\n[{index}/{len(resources)}] {path}")
                print_dry_run(
                    resource,
                    args.subscription_id,
                    args.resource_group,
                    args.workspace,
                )
            return 0

        token = get_access_token()
        failures = 0

        for index, (path, resource) in enumerate(resources, start=1):
            display_name = resource.get("properties", {}).get(
                "displayName",
                resource["name"],
            )
            print(f"[{index}/{len(resources)}] Deploying {display_name} ...")

            try:
                result = deploy_rule(
                    resource,
                    args.subscription_id,
                    args.resource_group,
                    args.workspace,
                    token,
                )
                deployed_name = result.get("name", resource["name"])
                print(f"PASS  {path} -> {deployed_name}")
            except (OSError, RuntimeError, json.JSONDecodeError) as error:
                print(f"ERROR {path}: {error}", file=sys.stderr)
                failures += 1

        if failures:
            print(
                f"\nFailed to deploy {failures} of {len(resources)} rule(s).",
                file=sys.stderr,
            )
            return 1

        print(f"\nDeployed {len(resources)} Sentinel rule(s).")
        return 0

    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
