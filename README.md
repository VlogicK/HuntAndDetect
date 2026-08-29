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

Hard validation errors return a non-zero exit code and fail CI. Examples include missing required fields, invalid UUIDs, unsupported severity values, invalid scheduling durations, malformed ATT&CK identifiers, and duplicate rule IDs.

Quality findings such as missing entity mappings are printed as warnings but do not fail CI.

GitHub Actions runs the same unit tests and repository validation automatically when detection or validator files change.

## Other detection content

This repository also includes YARA rules used for:

- Memory scanning of known malware families
- File-system and static-binary detection
