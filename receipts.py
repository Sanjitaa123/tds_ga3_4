"""Receipt validation and safe outcome classification."""


def validate_receipt(receipt, pending_dispatches, pending_approval=None):
    if not isinstance(receipt, dict):
        raise ValueError("Receipt must be a JSON object")
    receipt_id = receipt.get("receiptId")
    if not isinstance(receipt_id, str) or len(receipt_id.strip()) < 8:
        raise ValueError("receiptId must be a non-empty ID of at least eight characters")
    outcomes = receipt.get("outcomes", [])
    approvals = receipt.get("approvals", [])
    if not isinstance(outcomes, list) or not isinstance(approvals, list):
        raise ValueError("outcomes and approvals must be arrays")
    if outcomes and approvals:
        raise ValueError("A receipt cannot mix tool outcomes and approvals")
    pending = {
        (d.get("actionId"), d.get("callId"), d.get("attempt")): d
        for d in pending_dispatches
    }
    seen = set()
    for outcome in outcomes:
        if not isinstance(outcome, dict):
            raise ValueError("Each outcome must be an object")
        action_id, call_id, attempt = outcome.get("actionId"), outcome.get("callId"), outcome.get("attempt")
        if not isinstance(action_id, str) or len(action_id) < 8:
            raise ValueError("Invalid actionId")
        if not isinstance(call_id, str) or len(call_id) < 8:
            raise ValueError("Invalid callId")
        if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
            raise ValueError("Invalid attempt")
        key = (action_id, call_id, attempt)
        if key in seen:
            raise ValueError("Duplicate outcome")
        seen.add(key)
        if key not in pending:
            raise ValueError("Outcome does not match a pending call")
        status = outcome.get("status")
        if not isinstance(status, int) or isinstance(status, bool) or not 0 <= status <= 599:
            raise ValueError("Invalid outcome status")
        if status == 0 and outcome.get("errorType") != "timeout":
            raise ValueError("Status 0 must specify errorType timeout")
        if not isinstance(outcome.get("resultClass"), str) or not outcome["resultClass"]:
            raise ValueError("Missing resultClass")
        if not isinstance(outcome.get("nonce"), str) or len(outcome["nonce"]) < 8:
            raise ValueError("Invalid outcome nonce")
    for approval in approvals:
        if not isinstance(approval, dict):
            raise ValueError("Each approval must be an object")
        if not pending_approval or approval.get("approvalId") != pending_approval.get("approvalId"):
            raise ValueError("Approval does not match a pending approval request")
        if approval.get("decision") not in ("approved", "rejected"):
            raise ValueError("Approval decision must be approved or rejected")
        if not isinstance(approval.get("nonce"), str) or len(approval["nonce"]) < 8:
            raise ValueError("Invalid approval nonce")
    if not outcomes and not approvals:
        raise ValueError("Receipt must contain outcomes or approvals")
    return True


def find_dispatch(dispatches, action_id, call_id, attempt):
    for dispatch in dispatches:
        if (dispatch.get("actionId"), dispatch.get("callId"), dispatch.get("attempt")) == (action_id, call_id, attempt):
            return dispatch
    return None


def classify_outcome(status):
    if status == 0:
        return "timeout"
    if status == 503:
        return "retryable_error"
    if 200 <= status < 300:
        return "success"
    return "error"


def apply_receipt_outcomes(dispatches, receipt):
    """Pure helper retained for tests; main.py handles state transitions and retries."""
    updated = [dict(item) for item in dispatches]
    for outcome in receipt.get("outcomes", []):
        dispatch = find_dispatch(updated, outcome["actionId"], outcome["callId"], outcome["attempt"])
        if dispatch is None or dispatch.get("status") != "pending":
            raise ValueError("Dispatch is not pending")
        dispatch["httpStatus"] = outcome["status"]
        dispatch["status"] = "completed"
        dispatch["resultClass"] = outcome["resultClass"]
        dispatch["receiptId"] = receipt["receiptId"]
        dispatch["nonce"] = outcome["nonce"]
        dispatch["outcome"] = classify_outcome(outcome["status"])
    return updated


def prepare_retry(dispatch, traceparent=None):
    if dispatch.get("httpStatus") != 503 or dispatch.get("attempt") != 1:
        raise ValueError("Only an attempt-1 HTTP 503 can be retried")
    retry = dict(dispatch)
    retry["attempt"] = 2
    retry["status"] = "pending"
    if traceparent:
        retry["traceparent"] = traceparent
    for key in ("httpStatus", "resultClass", "receiptId", "nonce", "outcome", "errorType"):
        retry.pop(key, None)
    return retry
