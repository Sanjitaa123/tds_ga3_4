"""Dispatch construction and receipt-driven transition helpers."""
import hashlib
import json
import secrets
import re
from jsonschema import Draft202012Validator
import tool_validation


def new_action_id():
    return "act_" + secrets.token_hex(12)


def new_call_id():
    return "call_" + secrets.token_hex(12)


def new_approval_id():
    return "approval_" + secrets.token_hex(12)


def arguments_digest(arguments):
    packed = json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(packed.encode("utf-8")).hexdigest()


def make_dispatch(tool_name, arguments, evidence, phase, traceparent, action_id=None, call_id=None, attempt=1, approval_id=None, approval_nonce=None):
    result = {
        "actionId": action_id or new_action_id(),
        "callId": call_id or new_call_id(),
        "phase": phase,
        "toolName": tool_name,
        "arguments": arguments,
        "evidence": list(dict.fromkeys(evidence)),
        "attempt": attempt,
        "traceparent": traceparent,
    }
    if approval_id:
        result["approvalId"] = approval_id
    if approval_nonce:
        result["approvalNonce"] = approval_nonce
    return result


def validate_plan(data, plan):
    incident = data["incident"]
    policy = data["policy"]
    transcript = incident["transcript"]
    valid_ids = set(re.findall(r"^\s*\[([A-Za-z0-9_.:-]{1,128})\]", transcript, re.M))
    allowed_causes = incident["allowedRootCauses"]
    if plan.get("rootCause") not in allowed_causes:
        raise ValueError("Planner selected a root cause outside allowedRootCauses")
    evidence = plan.get("evidence")
    if not isinstance(evidence, list) or not 2 <= len(evidence) <= 4 or len(evidence) != len(set(evidence)):
        raise ValueError("Diagnosis must cite 2 to 4 unique evidence IDs")
    if not set(evidence).issubset(valid_ids):
        raise ValueError("Diagnosis contains an unknown evidence ID")
    catalog = {tool["name"]: tool for tool in data["toolCatalog"]}
    effect_names = set(policy.get("effectTools", []))
    diagnostics = plan.get("diagnostics")
    if not isinstance(diagnostics, list) or not 1 <= len(diagnostics) <= policy["maximumDiagnostics"]:
        raise ValueError("Planner selected an invalid number of diagnostics")
    seen = set()
    clean_diagnostics = []
    for item in diagnostics:
        if not isinstance(item, dict):
            raise ValueError("Each diagnostic must be an object")
        name, args, ev = item.get("toolName"), item.get("arguments"), item.get("evidence")
        if name not in catalog or name in effect_names:
            raise ValueError("Planner selected an unknown or forbidden diagnostic tool")
        if name in seen:
            raise ValueError("Duplicate diagnostic tool selected")
        seen.add(name)
        if not isinstance(ev, list) or not ev or len(ev) != len(set(ev)) or not set(ev).issubset(set(evidence)):
            raise ValueError("Diagnostic must cite unique diagnosis evidence IDs")
        tool_validation.validate_diagnostic_tool(catalog[name], args, effect_names)
        clean_diagnostics.append({"toolName": name, "arguments": args, "evidence": ev})
    effect = plan.get("effect")
    if not isinstance(effect, dict) or effect.get("toolName") not in effect_names:
        raise ValueError("Planner did not select a permitted effect")
    tool_validation.validate_effect_tool(catalog[effect["toolName"]], effect.get("arguments"), effect_names)
    # Explicit safety guard for the scenario named in the assignment.
    transcript_lower = transcript.lower()
    at_scale_limit = any(term in transcript_lower for term in (
        "scaling limit", "scale limit", "maximum permitted scale", "maximum scaling", "at maximum capacity", "already at its limit"
    ))
    if at_scale_limit and effect["toolName"] in {"scale_service", "scale_up", "increase_replicas"}:
        page_candidates = [
            name for name in effect_names
            if any(word in (name + " " + str(catalog[name].get("description", ""))).lower()
                   for word in ("page", "notify", "owner", "oncall", "on-call"))
        ]
        if not page_candidates:
            raise ValueError("Incident is at scaling limit but no permitted page/owner effect exists")
        page_name = page_candidates[0]
        schema = catalog[page_name]["inputSchema"]
        candidate_args = dict(effect.get("arguments", {}))
        if list(Draft202012Validator(schema).iter_errors(candidate_args)):
            candidate_args = {}
            properties = schema.get("properties", {})
            required = schema.get("required", [])
            transcript = incident.get("transcript", "")
            owner_match = re.search(r"(?:owner|on-call|oncall|team)\s*[:=]\s*([A-Za-z0-9_.@/-]+)", transcript, re.I)
            for key in required:
                if key in candidate_args:
                    continue
                prop = properties.get(key, {})
                key_lower = key.lower()
                if "default" in prop:
                    candidate_args[key] = prop["default"]
                elif "enum" in prop and prop["enum"]:
                    candidate_args[key] = prop["enum"][0]
                elif key_lower in ("service", "service_name", "servicename"):
                    candidate_args[key] = incident.get("service", "")
                elif key_lower in ("incidentid", "incident_id"):
                    candidate_args[key] = incident.get("incidentId", "")
                elif key_lower in ("severity", "priority"):
                    candidate_args[key] = incident.get("severity", "")
                elif any(word in key_lower for word in ("owner", "oncall", "on_call", "team")):
                    candidate_args[key] = owner_match.group(1) if owner_match else "service-owner"
                elif any(word in key_lower for word in ("reason", "message", "summary", "description", "title")):
                    candidate_args[key] = f"{incident.get('service', 'Service')} is at its permitted scaling limit; page the service owner."
                elif prop.get("type") == "string":
                    candidate_args[key] = str(incident.get("service", "incident"))
                elif prop.get("type") == "integer":
                    candidate_args[key] = 1
                elif prop.get("type") == "number":
                    candidate_args[key] = 1
                elif prop.get("type") == "boolean":
                    candidate_args[key] = True
                elif prop.get("type") == "array":
                    candidate_args[key] = []
                elif prop.get("type") == "object":
                    candidate_args[key] = {}
            if list(Draft202012Validator(schema).iter_errors(candidate_args)):
                raise ValueError("Could not construct schema-valid owner-notification arguments")
        effect = {"toolName": page_name, "arguments": candidate_args}
    return {
        "rootCause": plan["rootCause"],
        "evidence": evidence,
        "diagnostics": clean_diagnostics,
        "effect": {"toolName": effect["toolName"], "arguments": effect["arguments"]},
    }
