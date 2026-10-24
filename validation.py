"""Request and evidence validation."""
import re

EVIDENCE_RE = re.compile(r"^\s*\[([A-Za-z0-9_.:-]{1,128})\]")


def extract_evidence_ids(transcript):
    if not isinstance(transcript, str):
        raise ValueError("incident.transcript must be a string")
    found = []
    for line in transcript.splitlines():
        match = EVIDENCE_RE.match(line)
        if match:
            found.append(match.group(1))
    return list(dict.fromkeys(found))


def validate_request(data):
    if not isinstance(data, dict):
        raise ValueError("JSON object required")
    if data.get("profile") != "ga5-incident-agent/v2":
        raise ValueError("Unsupported profile")
    for key in ("runId", "agentName", "publicMarker"):
        value = data.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{key} must be a non-empty string")
    if len(data["runId"]) > 256 or len(data["publicMarker"]) > 256:
        raise ValueError("runId or publicMarker is too long")
    incident = data.get("incident")
    if not isinstance(incident, dict):
        raise ValueError("incident must be an object")
    for key in ("incidentId", "title", "service", "severity"):
        if not isinstance(incident.get(key), str) or not incident[key].strip():
            raise ValueError(f"incident.{key} must be a non-empty string")
    allowed = incident.get("allowedRootCauses")
    if not isinstance(allowed, list) or not allowed or not all(isinstance(x, str) and x for x in allowed):
        raise ValueError("allowedRootCauses must be a non-empty string array")
    if len(set(allowed)) != len(allowed):
        raise ValueError("allowedRootCauses must not contain duplicates")
    extract_evidence_ids(incident.get("transcript"))
    catalog = data.get("toolCatalog")
    if not isinstance(catalog, list) or not catalog:
        raise ValueError("toolCatalog must be a non-empty array")
    names = []
    for tool in catalog:
        if not isinstance(tool, dict) or not isinstance(tool.get("name"), str) or not tool["name"].strip():
            raise ValueError("Each tool needs a non-empty name")
        if not isinstance(tool.get("inputSchema"), dict):
            raise ValueError(f"Tool {tool['name']} is missing inputSchema")
        names.append(tool["name"])
    if len(names) != len(set(names)):
        raise ValueError("toolCatalog contains duplicate names")
    policy = data.get("policy")
    if not isinstance(policy, dict):
        raise ValueError("policy must be an object")
    maximum = policy.get("maximumDiagnostics")
    if not isinstance(maximum, int) or isinstance(maximum, bool) or not 1 <= maximum <= 3:
        raise ValueError("maximumDiagnostics must be an integer from 1 to 3")
    effects = policy.get("effectTools")
    if not isinstance(effects, list) or not all(isinstance(x, str) for x in effects):
        raise ValueError("policy.effectTools must be a string array")
    if not set(effects).issubset(set(names)):
        raise ValueError("policy.effectTools contains an unknown tool")
    approvals = policy.get("approvalRequiredFor", [])
    if not isinstance(approvals, list) or not all(isinstance(x, str) for x in approvals):
        raise ValueError("policy.approvalRequiredFor must be a string array")
    sensitive = data.get("sensitive", {})
    if not isinstance(sensitive, dict):
        raise ValueError("sensitive must be an object")
    return True


def collect_evidence_ids(transcript):
    return set(extract_evidence_ids(transcript))
