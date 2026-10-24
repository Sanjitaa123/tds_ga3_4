"""Public HTTPS GA5 incident agent API."""
import copy
import json
import os
import re
import time
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import planner
import receipts
import state_machine
import storage
import telemetry
import tool_validation
import validation

app = FastAPI(title="GA5 Incident Agent", docs_url=None, redoc_url=None)
storage.initialize()
MAX_BODY = 2 * 1024 * 1024
MAX_RESPONSE = 768 * 1024


def _json_response(payload, status_code=200):
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(raw) > MAX_RESPONSE:
        return JSONResponse({"detail": "Response exceeds 768 KiB"}, status_code=500)
    return JSONResponse(content=payload, status_code=status_code)


async def _read_json(request: Request):
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > MAX_BODY:
        raise ValueError("Request body too large")
    body = await request.body()
    if len(body) > MAX_BODY:
        raise ValueError("Request body too large")
    try:
        return json.loads(body)
    except Exception:
        raise ValueError("Invalid JSON")


def _safe_request(data):
    """Persist only fields needed later; never persist the sensitive object."""
    return {
        "profile": data["profile"],
        "runId": data["runId"],
        "agentName": data["agentName"],
        "publicMarker": data["publicMarker"],
        "incident": copy.deepcopy(data["incident"]),
        "toolCatalog": copy.deepcopy(data["toolCatalog"]),
        "policy": copy.deepcopy(data["policy"]),
    }


def _set_attr(span, key, value):
    attrs = span.setdefault("attributes", [])
    for item in attrs:
        if item.get("key") == key:
            item["value"] = telemetry.attr(key, value)["value"]
            return
    attrs.append(telemetry.attr(key, value))


def _span_by_id(state, span_id):
    for span in state["spans"]:
        if span.get("spanId") == span_id:
            return span
    return None


def _base_attrs(state):
    return {"ga5.run.id": state["runId"], "ga5.public.marker": state["publicMarker"]}


def _new_client_span(state, dispatch, parent_span_id, receipt=None):
    span_id = telemetry.new_span_id()
    attrs = _base_attrs(state)
    attrs.update({
        "ga5.action.id": dispatch["actionId"],
        "ga5.attempt": dispatch["attempt"],
        "http.request.method": "POST",
        "http.request.resend_count": dispatch["attempt"] - 1,
    })
    if receipt:
        attrs["ga5.receipt.id"] = receipt.get("receiptId")
        attrs["ga5.receipt.nonce"] = receipt.get("nonce")
    span = telemetry.make_span(
        state["traceId"], f"POST tool/{dispatch['toolName']}", 3, parent_span_id,
        attrs, span_id=span_id,
    )
    state["spans"].append(span)
    dispatch["traceparent"] = f"00-{state['traceId']}-{span_id}-{state['traceFlags']}"
    if state.get("tracestate"):
        dispatch["tracestate"] = state["tracestate"]
    dispatch["_clientSpanId"] = span_id
    return span


def _create_logical_tool_span(state, dispatch):
    attrs = _base_attrs(state)
    attrs.update({
        "ga5.action.id": dispatch["actionId"],
        "gen_ai.tool.name": dispatch["toolName"],
        "gen_ai.tool.call.id": dispatch["callId"],
        "gen_ai.operation.name": "execute_tool",
    })
    span = telemetry.make_span(
        state["traceId"], f"execute_tool {dispatch['toolName']}", 1,
        state["agentSpanId"], attrs,
    )
    state["spans"].append(span)
    state["logicalSpans"][dispatch["actionId"]] = span["spanId"]
    return span


def _issue_dispatch(state, dispatch, new_logical=True):
    if new_logical:
        logical = _create_logical_tool_span(state, dispatch)
        parent_id = logical["spanId"]
    else:
        parent_id = state["logicalSpans"][dispatch["actionId"]]
    _new_client_span(state, dispatch, parent_id)
    public_dispatch = {k: copy.deepcopy(v) for k, v in dispatch.items() if not k.startswith("_") and k != "status"}
    state["actionLog"].append(public_dispatch)
    state["pendingDispatches"].append(copy.deepcopy(dispatch))
    return public_dispatch


def _response_state(state):
    if state["status"] in ("completed", "failed"):
        return {
            "runId": state["runId"],
            "status": state["status"],
            "diagnosis": copy.deepcopy(state["diagnosis"]),
            "chosenEffect": state.get("chosenEffect"),
            "suppressed": copy.deepcopy(state["suppressed"]),
            "actionLog": copy.deepcopy(state["actionLog"]),
            "receiptLog": copy.deepcopy(state["receiptLog"]),
            "otlp": telemetry.wrap_otlp(state["spans"]),
        }
    return {
        "runId": state["runId"],
        "status": "waiting",
        "diagnosis": copy.deepcopy(state["diagnosis"]),
        "dispatches": [
            {k: copy.deepcopy(v) for k, v in d.items() if not k.startswith("_") and k != "status"}
            for d in state["pendingDispatches"]
        ],
        "approvals": copy.deepcopy(state.get("pendingApprovals", [])),
    }


def _terminal(state, succeeded, reason=None):
    state["status"] = "completed" if succeeded else "failed"
    if reason:
        state["suppressed"].append(reason)
    state["pendingDispatches"] = []
    state["pendingApprovals"] = []
    # close the agent span after the workflow has reached a terminal state
    agent = _span_by_id(state, state["agentSpanId"])
    if agent:
        agent["endTimeUnixNano"] = telemetry.now_ns()
    return state


def _maybe_issue_effect(state):
    if state["pendingDispatches"] or state["pendingApprovals"]:
        return
    diagnostic_logs = [x for x in state["receiptLog"] if "actionId" in x and state["phaseByAction"].get(x["actionId"]) == "diagnostic"]
    diag_action_ids = {d["actionId"] for d in state["actionLog"] if d.get("phase") == "diagnostic"}
    latest_by_action = {}
    for item in diagnostic_logs:
        latest_by_action[item["actionId"]] = item
    if not diag_action_ids or any(action not in latest_by_action for action in diag_action_ids):
        return
    if any(latest_by_action[action]["status"] == 0 or not 200 <= latest_by_action[action]["status"] < 300 for action in diag_action_ids):
        _terminal(state, False, "Planned effect suppressed because a diagnostic failed or timed out")
        return
    effect = state["effectPlan"]
    tool_name = effect["toolName"]
    args = effect["arguments"]
    policy = state["safeRequest"]["policy"]
    if tool_validation.is_destructive(tool_name, policy):
        approval_id = state.get("reservedApprovalId") or state_machine.new_approval_id()
        action_id = state.get("reservedEffectActionId") or state_machine.new_action_id()
        state["reservedApprovalId"] = approval_id
        state["reservedEffectActionId"] = action_id
        approval = {
            "approvalId": approval_id,
            "actionId": action_id,
            "toolName": tool_name,
            "argumentsDigest": state_machine.arguments_digest(args),
        }
        state["pendingApprovals"] = [approval]
        attrs = _base_attrs(state)
        attrs["ga5.approval.id"] = approval_id
        span = telemetry.make_span(state["traceId"], "approval_gate", 1, state["agentSpanId"], attrs)
        state["spans"].append(span)
        state["approvalGateSpanId"] = span["spanId"]
        state["status"] = "waiting"
        return
    state["chosenEffect"] = tool_name
    dispatch = state_machine.make_dispatch(
        tool_name, args, state["diagnosis"]["evidence"], "effect",
        "", action_id=state_machine.new_action_id(), call_id=state_machine.new_call_id(),
    )
    state["currentPhase"] = "effect"
    _issue_dispatch(state, dispatch, True)
    state["status"] = "waiting"


def _process_outcomes(state, receipt):
    incoming = receipt.get("outcomes", [])
    for outcome in incoming:
        dispatch = receipts.find_dispatch(
            state["pendingDispatches"], outcome["actionId"], outcome["callId"], outcome["attempt"]
        )
        if dispatch is None:
            raise ValueError("Outcome no longer matches a pending call")
        state["pendingDispatches"].remove(dispatch)
        status = outcome["status"]
        error_type = outcome.get("errorType")
        log_entry = {
            "receiptId": receipt["receiptId"],
            "actionId": outcome["actionId"],
            "callId": outcome["callId"],
            "attempt": outcome["attempt"],
            "status": status,
            "resultClass": outcome["resultClass"],
            "nonce": outcome["nonce"],
        }
        if error_type:
            log_entry["errorType"] = error_type
        state["receiptLog"].append(log_entry)
        span = _span_by_id(state, dispatch.get("_clientSpanId"))
        if span:
            span["endTimeUnixNano"] = telemetry.now_ns()
            _set_attr(span, "ga5.receipt.id", receipt["receiptId"])
            _set_attr(span, "ga5.receipt.nonce", outcome["nonce"])
            _set_attr(span, "http.response.status_code", status)
            if status == 0:
                _set_attr(span, "error.type", "timeout")
                span["status"] = telemetry.status(2, "timeout")
            elif status == 503:
                _set_attr(span, "error.type", "503")
                span["status"] = telemetry.status(2, "HTTP 503")
            elif not 200 <= status < 300:
                _set_attr(span, "error.type", str(status))
                span["status"] = telemetry.status(2, f"HTTP {status}")
            else:
                span["status"] = telemetry.status(0)
        logical_id = state["logicalSpans"].get(dispatch["actionId"])
        logical_span = _span_by_id(state, logical_id)
        if logical_span and (status != 503 or dispatch["attempt"] > 1):
            logical_span["endTimeUnixNano"] = telemetry.now_ns()
            if not 200 <= status < 300:
                logical_span["status"] = telemetry.status(2, "tool action failed")
        if status == 503 and dispatch["attempt"] == 1:
            retry = state_machine.make_dispatch(
                dispatch["toolName"], dispatch["arguments"], dispatch["evidence"], dispatch["phase"],
                "", action_id=dispatch["actionId"], call_id=dispatch["callId"], attempt=2,
                approval_id=dispatch.get("approvalId"), approval_nonce=dispatch.get("approvalNonce"),
            )
            _issue_dispatch(state, retry, False)
        elif status == 503 or status == 0 or not 200 <= status < 300:
            if dispatch["actionId"] not in state["failedActions"]:
                state["failedActions"].append(dispatch["actionId"])
        else:
            if dispatch["actionId"] not in state["successfulActions"]:
                state["successfulActions"].append(dispatch["actionId"])

    if state["pendingDispatches"]:
        return
    # All currently-issued diagnostics have receipts. Do not progress if a retry is pending.
    if state.get("currentPhase") == "diagnostic":
        _maybe_issue_effect(state)
    elif state.get("currentPhase") == "effect":
        effect_actions = [d["actionId"] for d in state["actionLog"] if d.get("phase") == "effect"]
        if effect_actions and effect_actions[-1] in state["successfulActions"]:
            _terminal(state, True)
        else:
            _terminal(state, False, "Effect failed; no further effect was dispatched")


def _process_approval(state, receipt):
    approval = receipt["approvals"][0]
    pending = state["pendingApprovals"][0]
    state["receiptLog"].append({
        "receiptId": receipt["receiptId"],
        "approvalId": approval["approvalId"],
        "decision": approval["decision"],
        "nonce": approval["nonce"],
    })
    gate = _span_by_id(state, state.get("approvalGateSpanId"))
    if gate:
        _set_attr(gate, "ga5.approval.id", approval["approvalId"])
        _set_attr(gate, "ga5.approval.receipt.nonce", approval["nonce"])
        gate["endTimeUnixNano"] = telemetry.now_ns()
    state["pendingApprovals"] = []
    if approval["decision"] != "approved":
        _terminal(state, False, "Effect suppressed because approval was rejected")
        return
    effect = state["effectPlan"]
    state["chosenEffect"] = effect["toolName"]
    dispatch = state_machine.make_dispatch(
        effect["toolName"], effect["arguments"], state["diagnosis"]["evidence"], "effect", "",
        action_id=pending["actionId"], call_id=state_machine.new_call_id(), attempt=1,
        approval_id=pending["approvalId"], approval_nonce=approval["nonce"],
    )
    _issue_dispatch(state, dispatch, True)
    state["currentPhase"] = "effect"
    state["status"] = "waiting"


def _build_initial_state(data, plan, incoming_traceparent, incoming_tracestate):
    context = telemetry.create_trace_context(incoming_traceparent, incoming_tracestate)
    run_id = data["runId"]
    marker = data["publicMarker"]
    safe = _safe_request(data)
    state = {
        "runId": run_id,
        "publicMarker": marker,
        "safeRequest": safe,
        "status": "waiting",
        "diagnosis": {"rootCause": plan["rootCause"], "evidence": plan["evidence"]},
        "effectPlan": plan["effect"],
        "chosenEffect": None,
        "suppressed": [],
        "actionLog": [],
        "receiptLog": [],
        "pendingDispatches": [],
        "pendingApprovals": [],
        "logicalSpans": {},
        "phaseByAction": {},
        "successfulActions": [],
        "failedActions": [],
        "currentPhase": "diagnostic",
        "traceId": context["trace_id"],
        "traceFlags": context["trace_flags"],
        "tracestate": context.get("tracestate"),
        "serverSpanId": context["span_id"],
        "agentSpanId": telemetry.new_span_id(),
        "spans": [],
        "reservedApprovalId": None,
        "reservedEffectActionId": None,
    }
    base = _base_attrs(state)
    server = telemetry.make_span(state["traceId"], "POST /v2/incidents", 2, context.get("parent_span_id"), base, span_id=state["serverSpanId"])
    state["spans"].append(server)
    agent = telemetry.make_span(state["traceId"], "invoke_agent incident-response", 1, state["serverSpanId"], base, span_id=state["agentSpanId"])
    state["spans"].append(agent)
    model_attrs = _base_attrs(state)
    model_attrs.update({"gen_ai.operation.name": "chat", "gen_ai.request.model": plan.get("_model") or os.getenv("OPENAI_MODEL", "gpt-4.1-mini")})
    state["spans"].append(telemetry.make_span(state["traceId"], "chat incident-plan", 3, state["agentSpanId"], model_attrs))
    diagnostics = plan["diagnostics"]
    for item in diagnostics:
        dispatch = state_machine.make_dispatch(item["toolName"], item["arguments"], item["evidence"], "diagnostic", "")
        state["phaseByAction"][dispatch["actionId"]] = "diagnostic"
        _issue_dispatch(state, dispatch, True)
    if len(diagnostics) > 1:
        links = [telemetry.link(state["traceId"], state["logicalSpans"][d["actionId"]]) for d in state["actionLog"] if d.get("phase") == "diagnostic"]
        state["spans"].append(telemetry.make_span(state["traceId"], "incident.join", 1, state["agentSpanId"], base, links=links))
    state["currentPhase"] = "diagnostic"
    # SERVER span records the initial request handling duration.
    state["spans"][0]["endTimeUnixNano"] = telemetry.now_ns()
    return state


@app.get("/")
def home():
    return _json_response({"message": "Incident Agent is running"})


@app.post("/v2/incidents")
async def create_incident(request: Request):
    try:
        data = await _read_json(request)
        validation.validate_request(data)
    except ValueError as exc:
        return _json_response({"detail": str(exc)}, 400)
    except Exception:
        return _json_response({"detail": "Invalid request"}, 400)
    run_id = data["runId"]
    request_hash = storage.fingerprint(data)
    existing = storage.get_incident(run_id)
    if existing:
        if existing["request_hash"] != request_hash:
            return _json_response({"detail": "Run ID conflict"}, 409)
        # Return exactly the original initial response. Never call the model on replay.
        return _json_response(json.loads(existing["initial_response_json"]))
    try:
        plan = planner.create_plan(data)
        clean_plan = state_machine.validate_plan(data, plan)
        state = _build_initial_state(data, {**clean_plan, "_model": plan.get("_model")}, request.headers.get("traceparent"), request.headers.get("tracestate"))
        initial_response = _response_state(state)
        storage.create_incident(run_id, request_hash, initial_response, state)
        return _json_response(initial_response)
    except Exception as exc:
        # Do not echo model prompts, request content, or sensitive values.
        message = str(exc)
        if any(word in message.lower() for word in ("api key", "authorization", "token", "sensitive")):
            message = "Could not create a valid incident plan"
        return _json_response({"detail": message[:300]}, 422)


@app.post("/v2/incidents/{runId}/receipts")
async def submit_receipt(runId: str, request: Request):
    try:
        receipt = await _read_json(request)
    except ValueError as exc:
        return _json_response({"detail": str(exc)}, 400)
    if not isinstance(receipt, dict):
        return _json_response({"detail": "JSON object required"}, 400)
    receipt_id = receipt.get("receiptId")
    if not isinstance(receipt_id, str) or len(receipt_id.strip()) < 8:
        return _json_response({"detail": "Invalid receiptId"}, 400)
    receipt_hash = storage.fingerprint(receipt)
    existing = storage.get_receipt(runId, receipt_id)
    if existing:
        if existing["receipt_hash"] != receipt_hash:
            return _json_response({"detail": "Receipt ID conflict"}, 409)
        return _json_response(json.loads(existing["response_json"]))
    row = storage.get_incident(runId)
    if not row:
        return _json_response({"detail": "Incident not found"}, 404)
    state = json.loads(row["state_json"])
    if state["status"] in ("completed", "failed"):
        return _json_response({"detail": "Incident is already terminal"}, 422)
    try:
        receipts.validate_receipt(receipt, state["pendingDispatches"], state["pendingApprovals"][0] if state["pendingApprovals"] else None)
        if receipt.get("approvals"):
            _process_approval(state, receipt)
        else:
            _process_outcomes(state, receipt)
        response = _response_state(state)
        # Receipt and updated state are persisted atomically before response.
        raced = storage.save_receipt_and_state(runId, receipt_id, receipt_hash, response, state)
        if raced:
            if raced["receipt_hash"] != receipt_hash:
                return _json_response({"detail": "Receipt ID conflict"}, 409)
            return _json_response(json.loads(raced["response_json"]))
        return _json_response(response)
    except ValueError as exc:
        return _json_response({"detail": str(exc)[:300]}, 422)
    except Exception:
        return _json_response({"detail": "Could not process receipt"}, 500)


@app.get("/v2/incidents/{runId}")
def get_incident(runId: str):
    row = storage.get_incident(runId)
    if not row:
        return _json_response({"detail": "Incident not found"}, 404)
    state = json.loads(row["state_json"])
    return _json_response(_response_state(state))
