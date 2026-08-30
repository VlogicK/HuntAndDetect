# KQL Detection Repository

This repository contains curated KQL detections and hunting queries built to identify malicious or suspicious behavior across Microsoft security products including:

- Microsoft Defender XDR
- Microsoft Sentinel
- Azure resource logs
- Defender for Identity
- Defender for Cloud Apps

The detection rules under `Detections/` use a Sentinel-aligned YAML authoring format. YAML is the source of truth; a later deployment phase will compile these files into Sentinel deployment JSON.

## Detection validation

Phase 1 includes a Python quality gate that validates every detection YAML before it can be merged.

Run it locally with:

```bash
python -m pip install -r requirements.txt
python -m pytest -q
python tools/validate.py
```

Hard validation errors return a non-zero exit code and fail CI. Quality findings such as missing entity mappings are printed as warnings but do not fail CI.

GitHub Actions runs the same unit tests and repository validation automatically when detection or validator files change.

## What can make a pull request fail?

A pull request can fail the detection validation check when a YAML rule violates one of the repository's required standards. The validator currently treats the following as blocking errors:

- **Invalid YAML** — the file cannot be parsed correctly.
- **Missing required fields** — required values such as `id`, `displayName`, `description`, `kind`, `severity`, `enabled`, `query`, scheduling fields, trigger configuration, tactics, or ATT&CK fields are missing.
- **Invalid rule ID** — `id` is not a valid UUID.
- **Duplicate rule ID** — two detection files use the same UUID.
- **Unsupported rule kind** — the rule uses a kind that the current validator does not support.
- **Invalid severity** — severity is not one of the supported Sentinel values: `Informational`, `Low`, `Medium`, or `High`.
- **Invalid enabled value** — `enabled` must be a YAML boolean (`true` or `false`).
- **Missing or empty KQL** — the `query` field is missing, is not a string, or contains no query content.
- **Invalid schedule format** — `queryFrequency` or `queryPeriod` does not use the expected ISO-8601 duration format, for example `PT5M` or `PT1H`.
- **Invalid schedule relationship** — `queryPeriod` is shorter than `queryFrequency`.
- **Invalid trigger configuration** — `triggerOperator` is unsupported or `triggerThreshold` is invalid.
- **Invalid ATT&CK tactic naming** — tactics must use the normalized Sentinel-style names expected by the repository, such as `DefenseEvasion` or `CommandAndControl`.
- **Malformed ATT&CK IDs** — technique or sub-technique identifiers do not follow ATT&CK formatting such as `T1112` or `T1059.001`.
- **Invalid incident configuration** — `incidentConfiguration` does not contain the expected structure or values.
- **Invalid event grouping configuration** — `eventGroupingSettings` does not contain a supported aggregation setting.

Some findings are intentionally **warnings only** and will not fail the pull request. Examples currently include:

- No ATT&CK techniques are mapped.
- No Sentinel entity mappings are configured.
- The detection description is unusually short.

Before opening a pull request, contributors can run the same checks locally:

```bash
python -m pytest -q
python tools/validate.py
```

A successful validation should exit with code `0`. Any blocking validation error exits with a non-zero status, which causes the GitHub Actions check to fail and prevents the rule from passing the Detection-as-Code quality gate.

## Other detection content

This repository also includes YARA rules used for:

- Memory scanning of known malware families
- File-system and static-binary detection
