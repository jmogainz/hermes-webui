"""Metadata-only native-auth control requests for Hermes WebUI.

The WebUI is a relay here. It validates the outer shape and live-stream
ownership, then forwards ciphertext to the existing AIAgent runtime. It never
logs, journals, decrypts, or projects envelope contents.
"""

from __future__ import annotations

import atexit
import re
import threading
from collections import Counter
from typing import Any, Callable


class NativeAuthRequestError(ValueError):
    """Safe request-validation error with no credential-bearing detail."""

    def __init__(
        self,
        message: str = "native auth request rejected",
        *,
        code: str = "rejected",
        stage: str = "request",
        retryable: bool = False,
        requires_remint: bool = False,
        status: int = 400,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.stage = stage
        self.retryable = retryable
        self.requires_remint = requires_remint
        self.status = status

    def public_payload(self) -> dict[str, Any]:
        return {
            "ok": False,
            "state": self.code,
            "code": self.code,
            "stage": self.stage,
            "retryable": self.retryable,
            "requires_remint": self.requires_remint,
        }


_OUTCOME_SPECS = {
    "submitted": (200, "complete", False, False),
    "cancelled": (200, "cancel", False, False),
    "busy": (409, "runtime", True, False),
    "replay": (409, "validate", False, True),
    "owner_mismatch": (409, "ownership", False, False),
    "rejected": (409, "validate", False, True),
    "expired": (410, "validate", False, True),
    "context_lost": (410, "ownership", False, True),
    "unsupported": (422, "preflight", False, False),
    "target_changed": (422, "preflight", False, True),
    "transient_runtime": (503, "runtime", True, False),
}


def _outcome_payload(code: str, *, ok: bool) -> dict[str, Any]:
    _status, stage, retryable, requires_remint = _OUTCOME_SPECS[code]
    return {
        "ok": ok,
        "state": code,
        "code": code,
        "stage": stage,
        "retryable": retryable,
        "requires_remint": requires_remint,
    }


def _outcome_error(code: str) -> NativeAuthRequestError:
    status, stage, retryable, requires_remint = _OUTCOME_SPECS[code]
    return NativeAuthRequestError(
        code=code,
        stage=stage,
        retryable=retryable,
        requires_remint=requires_remint,
        status=status,
    )


def _runtime_error(exc: Exception) -> NativeAuthRequestError:
    """Adapt structured or legacy runtime failures without exposing their text."""
    code = getattr(exc, "code", None)
    if code in _OUTCOME_SPECS:
        return _outcome_error(code)

    try:
        message = str(exc).lower()[:512]
    except Exception:
        message = ""
    if "replay" in message:
        mapped = "replay"
    elif "another session" in message or "owner" in message or "ownership" in message:
        mapped = "owner_mismatch"
    elif "expired" in message:
        mapped = "expired"
    elif "no longer active" in message or "context lost" in message or "runtime key mismatch" in message:
        mapped = "context_lost"
    elif "unsupported" in message or "adapter unavailable" in message:
        mapped = "unsupported"
    elif "target" in message and any(
        token in message
        for token in ("changed", "navigation", "document", "ambiguous", "disappeared", "match")
    ):
        mapped = "target_changed"
    elif "busy" in message or "in progress" in message:
        mapped = "busy"
    else:
        mapped = "transient_runtime"
    return _outcome_error(mapped)


_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
from datetime import datetime, timezone
from urllib.parse import urlsplit


_WIRE_ENVELOPE_KEYS = frozenset(
    {
        "type",
        "issued_by",
        "immutable",
        "context_id",
        "browser_session_id",
        "envelope_id",
        "provider_origin",
        "path",
        "cipher_suite",
        "key_id",
        "client_public_key",
        "nonce",
        "ciphertext",
        "tag",
        "journal_policy",
        "expires_at",
    }
)



def _opaque(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise NativeAuthRequestError(f"invalid native auth {name}")
    return value


def _canonical_origin(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise NativeAuthRequestError("invalid native auth provider origin")
    try:
        parsed = urlsplit(value.strip())
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            raise NativeAuthRequestError("native auth provider origin must be HTTPS")
        if parsed.username is not None or parsed.password is not None:
            raise NativeAuthRequestError("invalid native auth provider origin")
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise NativeAuthRequestError("native auth provider origin must be origin-only")
        host = parsed.hostname.rstrip(".").lower().encode("idna").decode("ascii")
        port = parsed.port
    except (TypeError, ValueError, UnicodeError):
        raise NativeAuthRequestError("invalid native auth provider origin") from None
    if port is not None and not 1 <= port <= 65535:
        raise NativeAuthRequestError("invalid native auth provider origin")
    authority = f"{host}:{port}" if port not in (None, 443) else host
    return f"https://{authority}"


def _safe_path(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 512:
        raise NativeAuthRequestError("invalid native auth path")
    path = value.strip() or "/"
    if not path.startswith("/") or "?" in path or "#" in path or "\\" in path:
        raise NativeAuthRequestError("native auth path must be query-free")
    if ".." in path.split("/") or any(ord(char) < 0x20 or ord(char) == 0x7F for char in path):
        raise NativeAuthRequestError("invalid native auth path")
    return path


def _encoded(value: Any, *, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise NativeAuthRequestError(f"invalid native auth {name} encoding")
    return value


def _expiry(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value):
        raise NativeAuthRequestError("invalid native auth expiry")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError, OverflowError):
        raise NativeAuthRequestError("invalid native auth expiry") from None
    return value


def _validated_envelope(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _WIRE_ENVELOPE_KEYS:
        raise NativeAuthRequestError("native auth submit accepts ciphertext envelope only")
    if value.get("type") != "semreh.native-secret-envelope.v1" or value.get("issued_by") != "semreh-native" or value.get("immutable") is not True:
        raise NativeAuthRequestError("unsupported native auth envelope")
    _opaque(value.get("context_id"), "context")
    _opaque(value.get("browser_session_id"), "browser session")
    _opaque(value.get("envelope_id"), "envelope")
    _opaque(value.get("key_id"), "runtime key")
    if value.get("cipher_suite") != "AES-256-GCM" or value.get("journal_policy") != "never":
        raise NativeAuthRequestError("native auth envelope policy is invalid")
    if value.get("provider_origin") != _canonical_origin(value.get("provider_origin")):
        raise NativeAuthRequestError("native auth provider origin is not canonical")
    _safe_path(value.get("path"))
    _encoded(value.get("client_public_key"), name="client public key", maximum=128)
    _encoded(value.get("nonce"), name="nonce", maximum=64)
    _encoded(value.get("ciphertext"), name="ciphertext", maximum=131072)
    _encoded(value.get("tag"), name="tag", maximum=128)
    _expiry(value.get("expires_at"))
    return dict(value)


_WIRE_COMPONENT_KINDS = frozenset(
    {
        "email", "username", "identifier", "phone", "organization", "tenant",
        "access_code", "password", "passcode", "pin", "secret", "totp_code",
        "sms_code", "email_code", "one_time_code", "verification_code",
        "recovery_code", "backup_code", "security_answer", "date_of_birth",
        "numeric", "text", "select", "radio", "checkbox", "consent", "submit",
        "sso_continue", "email_magic_link", "phone_verification", "passkey",
        "security_key", "captcha", "push_approval", "device_approval", "cancel",
    }
)
_WIRE_STATUS_KINDS = frozenset({"available", "focused", "awaiting_browser", "completed", "cancelled", "blocked", "unavailable"})
_WIRE_CANCEL_REASONS = frozenset({"user_cancelled", "browser_cancelled", "expired", "navigation_cancelled"})


def _event_text(value: Any, *, name: str, maximum: int, allow_empty: bool = True) -> str:
    if not isinstance(value, str) or len(value) > maximum or (not allow_empty and not value.strip()):
        raise NativeAuthRequestError(f"invalid native auth {name}")
    value = value.strip()
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise NativeAuthRequestError(f"invalid native auth {name}")
    return value


def _project_target_ref(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise NativeAuthRequestError("native auth target reference is invalid")
    allowed = {"issued_by", "immutable", "ref_id", "strategy", "selector", "role", "label", "frame_handle", "cdp_handle", "locator_handle"}
    if set(value) - allowed:
        raise NativeAuthRequestError("native auth target reference contains unsupported metadata")
    if value.get("issued_by") != "browser" or value.get("immutable") is not True:
        raise NativeAuthRequestError("native auth target reference is not browser-issued")
    ref_id = _opaque(value.get("ref_id"), "target reference")
    strategy = _event_text(value.get("strategy"), name="target strategy", maximum=16, allow_empty=False)
    if strategy not in {"css", "xpath", "role", "label", "cdp", "playwright"}:
        raise NativeAuthRequestError("native auth target strategy is unsupported")
    result: dict[str, Any] = {"issued_by": "browser", "immutable": True, "ref_id": ref_id, "strategy": strategy}
    if strategy in {"css", "xpath"}:
        selector = _event_text(value.get("selector"), name="target selector", maximum=160, allow_empty=False)
        if any(token in selector.lower() for token in ("javascript:", "<script", "innerhtml")):
            raise NativeAuthRequestError("native auth target selector is unsafe")
        result["selector"] = selector
    elif strategy == "role":
        role = _event_text(value.get("role"), name="target role", maximum=32, allow_empty=False)
        if role not in {"textbox", "button", "link", "combobox", "checkbox", "radio", "image", "option", "menuitem", "switch"}:
            raise NativeAuthRequestError("native auth target role is unsupported")
        result["role"] = role
        result["label"] = _event_text(value.get("label"), name="target label", maximum=80, allow_empty=False)
    elif strategy == "label":
        result["label"] = _event_text(value.get("label"), name="target label", maximum=80, allow_empty=False)
    elif strategy == "cdp":
        result["cdp_handle"] = _opaque(value.get("cdp_handle"), "CDP target")
    else:
        result["locator_handle"] = _opaque(value.get("locator_handle"), "locator target")
    return result


def _project_binding(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise NativeAuthRequestError("native auth binding is invalid")
    allowed = {"issued_by", "immutable", "tab_handle", "frame_handle", "document_generation", "visibility", "editability", "match_count", "target_ref"}
    if set(value) != allowed:
        raise NativeAuthRequestError("native auth binding contains unsupported metadata")
    if value.get("issued_by") != "browser" or value.get("immutable") is not True:
        raise NativeAuthRequestError("native auth binding is not browser-issued")
    for key, label in (("tab_handle", "tab"), ("frame_handle", "frame"), ("document_generation", "document generation")):
        _opaque(value.get(key), label)
    if value.get("visibility") != "visible" or value.get("editability") not in {"editable", "not_editable"} or value.get("match_count") != 1:
        raise NativeAuthRequestError("native auth binding is not safe")
    return {
        "issued_by": "browser",
        "immutable": True,
        "tab_handle": value["tab_handle"],
        "frame_handle": value["frame_handle"],
        "document_generation": value["document_generation"],
        "visibility": "visible",
        "editability": value["editability"],
        "match_count": 1,
        "target_ref": _project_target_ref(value["target_ref"]),
    }


def _project_native_component(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise NativeAuthRequestError("native auth component must be an object")
    allowed = {"type", "issued_by", "immutable", "context_id", "browser_session_id", "component_id", "field", "action_handle", "kind", "label", "provider_origin", "path", "runtime_public_key", "key_id", "expires_at", "binding"}
    if set(value) != allowed:
        raise NativeAuthRequestError("native auth component contains unsupported metadata")
    if value.get("type") != "semreh.native-component.v1" or value.get("issued_by") != "browser" or value.get("immutable") is not True:
        raise NativeAuthRequestError("native auth component is unsupported")
    for key, label in (("context_id", "context"), ("browser_session_id", "browser session"), ("component_id", "component"), ("field", "field"), ("action_handle", "action"), ("key_id", "runtime key")):
        _opaque(value.get(key), label)
    kind = _event_text(value.get("kind"), name="component kind", maximum=32, allow_empty=False)
    if kind not in _WIRE_COMPONENT_KINDS:
        raise NativeAuthRequestError("native auth component kind is unsupported")
    origin = _canonical_origin(value.get("provider_origin"))
    if value.get("provider_origin") != origin:
        raise NativeAuthRequestError("native auth component origin is not canonical")
    path = _safe_path(value.get("path"))
    # Validate the browser-owned binding at the trust boundary, but never copy
    # target references, selectors, frame handles, or matching internals onto
    # the WebUI/iOS wire. The opaque field/action handles are the only target
    # capabilities the native client needs.
    _project_binding(value["binding"])
    return {
        "type": "semreh.native-component.v1",
        "issued_by": "browser",
        "immutable": True,
        "context_id": value["context_id"],
        "browser_session_id": value["browser_session_id"],
        "component_id": value["component_id"],
        "field": value["field"],
        "action_handle": value["action_handle"],
        "kind": kind,
        "label": _event_text(value.get("label"), name="component label", maximum=120, allow_empty=False),
        "provider_origin": origin,
        "path": path,
        "runtime_public_key": _encoded(value.get("runtime_public_key"), name="runtime key", maximum=128),
        "key_id": value["key_id"],
        "expires_at": _expiry(value.get("expires_at")),
    }


def _project_native_state(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise NativeAuthRequestError("native auth state must be an object")
    allowed = {"type", "issued_by", "immutable", "context_id", "browser_session_id", "component_id", "action_handle", "kind", "provider_origin", "path", "status", "field_ids", "action_id", "cancel_reason"}
    if set(value) - allowed:
        raise NativeAuthRequestError("native auth state contains unsupported metadata")
    required = {"type", "issued_by", "immutable", "context_id", "browser_session_id", "component_id", "action_handle", "kind", "provider_origin", "path", "status"}
    if set(value) & required != required:
        raise NativeAuthRequestError("native auth state is incomplete")
    if value.get("type") != "semreh.native-component-state.v1" or value.get("issued_by") != "browser" or value.get("immutable") is not True:
        raise NativeAuthRequestError("native auth state is unsupported")
    for key, label in (("context_id", "context"), ("browser_session_id", "browser session"), ("component_id", "component"), ("action_handle", "action")):
        _opaque(value.get(key), label)
    kind = _event_text(value.get("kind"), name="state kind", maximum=32, allow_empty=False)
    if kind not in _WIRE_COMPONENT_KINDS:
        raise NativeAuthRequestError("native auth state kind is unsupported")
    status = _event_text(value.get("status"), name="status", maximum=32, allow_empty=False)
    if status not in _WIRE_STATUS_KINDS:
        raise NativeAuthRequestError("native auth state status is unsupported")
    origin = _canonical_origin(value.get("provider_origin"))
    if value.get("provider_origin") != origin:
        raise NativeAuthRequestError("native auth state origin is not canonical")
    result: dict[str, Any] = {
        "type": "semreh.native-component-state.v1",
        "issued_by": "browser",
        "immutable": True,
        "context_id": value["context_id"],
        "browser_session_id": value["browser_session_id"],
        "component_id": value["component_id"],
        "action_handle": value["action_handle"],
        "kind": kind,
        "provider_origin": origin,
        "path": _safe_path(value.get("path")),
        "status": status,
    }
    if "field_ids" in value:
        field_ids = value["field_ids"]
        if not isinstance(field_ids, list) or len(field_ids) > 32 or not all(isinstance(item, str) and _ID_RE.fullmatch(item) for item in field_ids):
            raise NativeAuthRequestError("native auth state field IDs are invalid")
        result["field_ids"] = list(field_ids)
    if "action_id" in value:
        result["action_id"] = _event_text(value["action_id"], name="action ID", maximum=128, allow_empty=False)
    if "cancel_reason" in value:
        reason = _event_text(value["cancel_reason"], name="cancel reason", maximum=32, allow_empty=False)
        if status != "cancelled" or reason not in _WIRE_CANCEL_REASONS:
            raise NativeAuthRequestError("native auth cancellation metadata is invalid")
        result["cancel_reason"] = reason
    return result


def project_native_auth_event(event: str, value: Any) -> dict[str, Any]:
    """Project one trusted runtime event into a closed metadata-only wire shape."""
    if event == "native_component":
        return _project_native_component(value)
    if event == "native_component_state":
        return _project_native_state(value)
    raise NativeAuthRequestError("unsupported native auth event")


_RUNTIME_STATE_OUTCOMES = {
    "submitted": "submitted",
    "cancelled": "cancelled",
    "expired": "expired",
    "failed": "rejected",
    "accepted": "transient_runtime",
    "filled": "transient_runtime",
}


def _adapt_runtime_result(result: Any, *, success_states: frozenset[str]) -> dict[str, Any]:
    """Convert one runtime state into the closed HTTP outcome taxonomy."""
    if not isinstance(result, dict):
        raise _outcome_error("transient_runtime")
    state = result.get("state")
    code = _RUNTIME_STATE_OUTCOMES.get(state)
    if code is None:
        raise _outcome_error("transient_runtime")
    if state in success_states:
        return _outcome_payload(code, ok=True)
    raise _outcome_error(code)


_NATIVE_AUTH_DIAGNOSTICS_LOCK = threading.Lock()
_NATIVE_AUTH_COUNTERS: Counter[str] = Counter()
_BOUND_NATIVE_AUTH_TASKS: set[str] = set()


def _native_runtime():
    from tools.native_auth_runtime import native_auth_runtime

    return native_auth_runtime


def _count_native_auth(name: str) -> None:
    with _NATIVE_AUTH_DIAGNOSTICS_LOCK:
        _NATIVE_AUTH_COUNTERS[name] += 1


def bind_native_auth_task(task_id: str, callback, *, runtime=None) -> bool:
    """Bind one callback and track only its opaque-free aggregate lifetime."""
    task_key = str(task_id or "").strip()
    if not task_key or not callable(callback):
        return False
    active_runtime = runtime or _native_runtime()
    active_runtime.register_component_callback(task_key, callback)
    with _NATIVE_AUTH_DIAGNOSTICS_LOCK:
        _BOUND_NATIVE_AUTH_TASKS.add(task_key)
        _NATIVE_AUTH_COUNTERS["tasks_bound"] += 1
    return True


def close_native_auth_task(task_id: str, *, runtime=None) -> int:
    """Detach a task callback and terminally clean all of its runtime contexts."""
    task_key = str(task_id or "").strip()
    if not task_key:
        return 0
    active_runtime = runtime or _native_runtime()
    try:
        cleaned = max(0, int(active_runtime.close_task(task_key)))
    except Exception:
        _count_native_auth("task_close_failures")
        return 0
    with _NATIVE_AUTH_DIAGNOSTICS_LOCK:
        _BOUND_NATIVE_AUTH_TASKS.discard(task_key)
        _NATIVE_AUTH_COUNTERS["tasks_closed"] += 1
        _NATIVE_AUTH_COUNTERS["contexts_closed"] += cleaned
    return cleaned


def detach_native_auth_task(task_id: str, *, runtime=None) -> bool:
    """Detach a terminal task callback after its runtime context self-closes."""
    task_key = str(task_id or "").strip()
    if not task_key:
        return False
    active_runtime = runtime or _native_runtime()
    try:
        active_runtime.register_component_callback(task_key, None)
    except Exception:
        _count_native_auth("task_detach_failures")
        return False
    with _NATIVE_AUTH_DIAGNOSTICS_LOCK:
        _BOUND_NATIVE_AUTH_TASKS.discard(task_key)
        _NATIVE_AUTH_COUNTERS["tasks_detached"] += 1
    return True


def close_all_native_auth_tasks(*, runtime=None) -> int:
    """Best-effort process-shutdown cleanup for every tracked task."""
    active_runtime = runtime or _native_runtime()
    with _NATIVE_AUTH_DIAGNOSTICS_LOCK:
        task_ids = tuple(_BOUND_NATIVE_AUTH_TASKS)
    for task_id in task_ids:
        close_native_auth_task(task_id, runtime=active_runtime)
    return len(task_ids)


def native_auth_diagnostics_snapshot() -> dict[str, Any]:
    """Return aggregate counters only; never task/component identifiers."""
    with _NATIVE_AUTH_DIAGNOSTICS_LOCK:
        return {
            "bound_tasks": len(_BOUND_NATIVE_AUTH_TASKS),
            "counters": dict(sorted(_NATIVE_AUTH_COUNTERS.items())),
        }


def _close_native_auth_at_exit() -> None:
    try:
        close_all_native_auth_tasks()
    except Exception:
        pass


atexit.register(_close_native_auth_at_exit)


def _live_agent(body: dict[str, Any], agent_lookup: Callable[[str], Any]) -> Any:
    """Return the authenticated live agent owning the submitted stream."""
    stream_id = _opaque(body.get("stream_id"), "stream")
    try:
        agent = agent_lookup(stream_id)
    except Exception:
        agent = None
    if agent is None:
        raise NativeAuthRequestError("native auth stream is not active")
    session_id = _opaque(body.get("session_id"), "session")
    if str(getattr(agent, "session_id", "")) != session_id:
        raise NativeAuthRequestError("native auth session ownership mismatch")
    return agent


def submit_native_auth_request(body: Any, *, agent_lookup: Callable[[str], Any]) -> dict[str, Any]:
    """Forward one ciphertext envelope to the live AIAgent browser runtime."""
    if not isinstance(body, dict) or set(body) != {"session_id", "stream_id", "envelope"}:
        raise NativeAuthRequestError("native auth submit accepts ciphertext envelope only")
    agent = _live_agent(body, agent_lookup)
    envelope = _validated_envelope(body.get("envelope"))
    try:
        result = agent.submit_native_auth_envelope(envelope)
    except NativeAuthRequestError:
        raise
    except Exception as exc:
        _count_native_auth("submit_failures")
        raise _runtime_error(exc) from None
    try:
        payload = _adapt_runtime_result(result, success_states=frozenset({"submitted", "cancelled"}))
    except NativeAuthRequestError:
        _count_native_auth("submit_failures")
        raise
    _count_native_auth("submit_successes")
    return payload


def cancel_native_auth_request(body: Any, *, agent_lookup: Callable[[str], Any]) -> dict[str, Any]:
    if not isinstance(body, dict) or set(body) != {"session_id", "stream_id", "component_id"}:
        raise NativeAuthRequestError("native auth cancel has an invalid shape")
    agent = _live_agent(body, agent_lookup)
    component_id = _opaque(body.get("component_id"), "component")
    try:
        result = agent.cancel_native_component(component_id)
    except NativeAuthRequestError:
        _count_native_auth("cancel_failures")
        raise
    except Exception as exc:
        _count_native_auth("cancel_failures")
        raise _runtime_error(exc) from None
    try:
        payload = _adapt_runtime_result(result, success_states=frozenset({"cancelled"}))
    except NativeAuthRequestError:
        _count_native_auth("cancel_failures")
        raise
    _count_native_auth("cancel_successes")
    return payload


__all__ = [
    "NativeAuthRequestError",
    "bind_native_auth_task",
    "close_all_native_auth_tasks",
    "close_native_auth_task",
    "detach_native_auth_task",
    "native_auth_diagnostics_snapshot",
    "project_native_auth_event",
    "submit_native_auth_request",
    "cancel_native_auth_request",
]
