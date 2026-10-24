"""W3C trace-context helpers and OTLP JSON trace construction."""
import re
import secrets
import time

TRACEPARENT_RE = re.compile(r"^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$", re.I)


def new_trace_id():
    while True:
        value = secrets.token_hex(16)
        if value != "0" * 32:
            return value


def new_span_id():
    while True:
        value = secrets.token_hex(8)
        if value != "0" * 16:
            return value


def parse_traceparent(value):
    if not isinstance(value, str):
        return None
    match = TRACEPARENT_RE.fullmatch(value.strip())
    if not match:
        return None
    version, trace_id, parent_span_id, flags = [part.lower() for part in match.groups()]
    if version == "ff" or trace_id == "0" * 32 or parent_span_id == "0" * 16:
        return None
    if version == "00" and len(value.strip().split("-")) != 4:
        return None
    return {"trace_id": trace_id, "parent_span_id": parent_span_id, "trace_flags": flags}


def create_trace_context(traceparent=None, tracestate=None):
    incoming = parse_traceparent(traceparent)
    if incoming:
        return {
            **incoming,
            "span_id": new_span_id(),
            "tracestate": tracestate if isinstance(tracestate, str) and tracestate.strip() else None,
        }
    return {
        "trace_id": new_trace_id(),
        "parent_span_id": None,
        "span_id": new_span_id(),
        "trace_flags": "01",
        "tracestate": None,
    }


def make_traceparent(context):
    return f"00-{context['trace_id']}-{context['span_id']}-{context.get('trace_flags', '01')}"


def now_ns():
    return str(time.time_ns())


def attr(key, value):
    if isinstance(value, bool):
        typed = {"boolValue": value}
    elif isinstance(value, int) and not isinstance(value, bool):
        typed = {"intValue": str(value)}
    elif isinstance(value, float):
        typed = {"doubleValue": value}
    else:
        typed = {"stringValue": str(value)}
    return {"key": key, "value": typed}


def status(code=0, message=None):
    result = {"code": code}
    if message:
        result["message"] = message
    return result


def make_span(trace_id, name, kind, parent_span_id, attributes, start=None, end=None,
              span_id=None, status_code=0, status_message=None, links=None):
    start = start or now_ns()
    end = end or start
    span = {
        "traceId": trace_id,
        "spanId": span_id or new_span_id(),
        "name": name,
        "kind": kind,
        "startTimeUnixNano": start,
        "endTimeUnixNano": end,
        "attributes": [attr(k, v) for k, v in attributes.items() if v is not None],
        "status": status(status_code, status_message),
    }
    if parent_span_id:
        span["parentSpanId"] = parent_span_id
    if links:
        span["links"] = links
    return span


def link(trace_id, span_id):
    return {"traceId": trace_id, "spanId": span_id, "attributes": []}


def wrap_otlp(spans):
    if not spans:
        return {"resourceSpans": [{"scopeSpans": [{"spans": []}]}]}
    trace_id = spans[0]["traceId"]
    return {
        "resourceSpans": [{
            "resource": {"attributes": []},
            "scopeSpans": [{
                "scope": {"name": "ga5-incident-agent", "version": "1.0.0"},
                "spans": spans,
            }],
        }]
    }
