"""WebUI native-auth control-plane contract tests."""

from __future__ import annotations

import json
from io import BytesIO
from urllib.parse import urlparse

import pytest

from api.native_auth import (
    NativeAuthRequestError,
    bind_native_auth_task,
    cancel_native_auth_request,
    close_all_native_auth_tasks,
    close_native_auth_task,
    native_auth_diagnostics_snapshot,
    project_native_auth_event,
    submit_native_auth_request,
)


class _Agent:
    session_id = "session-1"

    def __init__(self):
        self.submitted = []
        self.cancelled = []

    def submit_native_auth_envelope(self, envelope):
        self.submitted.append(envelope)
        return {
            "schema": "semreh.native-component-state.v1",
            "component_id": envelope.get("component_id") or envelope["context_id"],
            "state": "submitted",
        }

    def cancel_native_component(self, component_id):
        self.cancelled.append(component_id)
        return {
            "schema": "semreh.native-component-state.v1",
            "component_id": component_id,
            "state": "cancelled",
        }


_WIRE_COMPONENT = {
    "type": "semreh.native-component.v1",
    "issued_by": "browser",
    "immutable": True,
    "context_id": "ctx_12345678",
    "browser_session_id": "bs_12345678",
    "component_id": "cmp_12345678",
    "field": "fld_12345678",
    "action_handle": "act_12345678",
    "kind": "secret",
    "label": "Password",
    "provider_origin": "https://accounts.example.test",
    "path": "/login",
    "runtime_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "key_id": "rt_12345678",
    "expires_at": "2099-01-01T00:00:00Z",
    "binding": {
        "issued_by": "browser",
        "immutable": True,
        "tab_handle": "tab_12345678",
        "frame_handle": "frame_12345678",
        "document_generation": "doc_12345678",
        "visibility": "visible",
        "editability": "editable",
        "match_count": 1,
        "target_ref": {
            "issued_by": "browser",
            "immutable": True,
            "ref_id": "ref_12345678",
            "strategy": "css",
            "selector": "input[type=password]",
        },
    },
}


_WIRE_ENVELOPE = {
    "type": "semreh.native-secret-envelope.v1",
    "issued_by": "semreh-native",
    "immutable": True,
    "context_id": "ctx_12345678",
    "browser_session_id": "bs_12345678",
    "envelope_id": "env_12345678",
    "provider_origin": "https://accounts.example.test",
    "path": "/login",
    "cipher_suite": "AES-256-GCM",
    "key_id": "rt_12345678",
    "client_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "nonce": "AAAAAAAAAAAAAAAA",
    "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA",
    "tag": "AAAAAAAAAAAAAAAAAAAAAA",
    "journal_policy": "never",
    "expires_at": "2099-01-01T00:00:00Z",
}


_ENVELOPE = {
    "schema": "semreh.native-secret-envelope.v1",
    "component_id": "cmp_12345678",
    "sequence": 1,
    "key_id": "rt_12345678",
    "client_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "nonce": "AAAAAAAAAAAAAAAA",
    "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA",
    "tag": "AAAAAAAAAAAAAAAAAAAAAA",
}


def test_submit_routes_only_ciphertext_to_live_session_agent():
    agent = _Agent()
    payload = submit_native_auth_request(
        {
            "session_id": "session-1",
            "stream_id": "stream-1",
            "envelope": _WIRE_ENVELOPE,
        },
        agent_lookup=lambda stream_id: agent if stream_id == "stream-1" else None,
    )

    assert payload["ok"] is True
    assert payload["state"] == "submitted"
    assert agent.submitted == [_WIRE_ENVELOPE]


def test_wire_submit_forwards_ciphertext_only_to_live_session_agent():
    agent = _Agent()
    payload = submit_native_auth_request(
        {
            "session_id": "session-1",
            "stream_id": "stream-1",
            "envelope": _WIRE_ENVELOPE,
        },
        agent_lookup=lambda stream_id: agent if stream_id == "stream-1" else None,
    )
    assert payload["ok"] is True
    assert payload["state"] == "submitted"
    assert agent.submitted == [_WIRE_ENVELOPE]


def test_submit_rejects_plaintext_fields_and_unknown_body_keys():
    agent = _Agent()
    with pytest.raises(NativeAuthRequestError):
        submit_native_auth_request(
            {
                "session_id": "session-1",
                "stream_id": "stream-1",
                "envelope": _WIRE_ENVELOPE,
                "fields": {"password": "must-not-cross"},
            },
            agent_lookup=lambda _: agent,
        )
    with pytest.raises(NativeAuthRequestError):
        submit_native_auth_request(
            {
                "session_id": "session-1",
                "stream_id": "stream-1",
                "envelope": {"component_id": "cmp_12345678", "value": "must-not-cross"},
            },
            agent_lookup=lambda _: agent,
        )


def test_submit_rejects_wrong_session_or_missing_live_agent():
    agent = _Agent()
    with pytest.raises(NativeAuthRequestError, match="session"):
        submit_native_auth_request(
            {"session_id": "other", "stream_id": "stream-1", "envelope": _WIRE_ENVELOPE},
            agent_lookup=lambda _: agent,
        )
    with pytest.raises(NativeAuthRequestError, match="active"):
        submit_native_auth_request(
            {"session_id": "session-1", "stream_id": "missing-stream", "envelope": _WIRE_ENVELOPE},
            agent_lookup=lambda _: None,
        )


def test_cancel_returns_opaque_state_and_requires_live_owner():
    agent = _Agent()
    payload = cancel_native_auth_request(
        {"session_id": "session-1", "stream_id": "stream-1", "component_id": "cmp_12345678"},
        agent_lookup=lambda _: agent,
    )
    assert payload["state"] == "cancelled"
    assert agent.cancelled == ["cmp_12345678"]


def test_submit_rejects_legacy_envelope_shape():
    agent = _Agent()
    with pytest.raises(NativeAuthRequestError, match="ciphertext envelope"):
        submit_native_auth_request(
            {
                "session_id": "session-1",
                "stream_id": "stream-1",
                "envelope": _ENVELOPE,
            },
            agent_lookup=lambda _: agent,
        )


def test_submit_rejects_unsafe_wire_origin_path_and_encoding():
    agent = _Agent()
    for envelope in (
        {**_WIRE_ENVELOPE, "provider_origin": "http://accounts.example.test"},
        {**_WIRE_ENVELOPE, "path": "/login?next=https://evil.example"},
        {**_WIRE_ENVELOPE, "path": "/login#fragment"},
        {**_WIRE_ENVELOPE, "client_public_key": "not base64!!!"},
    ):
        with pytest.raises(NativeAuthRequestError):
            submit_native_auth_request(
                {"session_id": "session-1", "stream_id": "stream-1", "envelope": envelope},
                agent_lookup=lambda _: agent,
            )


def test_project_native_auth_component_allows_only_safe_metadata():
    projected = project_native_auth_event("native_component", _WIRE_COMPONENT)

    assert projected["type"] == "semreh.native-component.v1"
    assert projected["label"] == "Password"
    assert projected["action_handle"] == "act_12345678"
    assert "binding" not in projected
    wire = json.dumps(projected).lower()
    for forbidden in ("selector", "target_ref", "envelope", "value", "input[type=password]"):
        assert forbidden not in wire


@pytest.mark.parametrize(
    "kind",
    ["email_magic_link", "phone_verification", "security_key", "device_approval"],
)
def test_project_native_auth_component_supports_complete_runtime_action_kinds(kind):
    projected = project_native_auth_event("native_component", {**_WIRE_COMPONENT, "kind": kind})
    assert projected["kind"] == kind


@pytest.mark.parametrize(
    "status",
    ["available", "focused", "awaiting_browser", "completed", "cancelled", "blocked", "unavailable"],
)
def test_project_native_auth_state_supports_every_wire_status_without_action_internals(status):
    state = {
        "type": "semreh.native-component-state.v1",
        "issued_by": "browser",
        "immutable": True,
        "context_id": "ctx_12345678",
        "browser_session_id": "bs_12345678",
        "component_id": "cmp_12345678",
        "action_handle": "act_12345678",
        "kind": "device_approval",
        "provider_origin": "https://accounts.example.test",
        "path": "/login",
        "status": status,
    }
    if status == "cancelled":
        state["cancel_reason"] = "expired"

    projected = project_native_auth_event("native_component_state", state)

    assert projected["status"] == status
    assert projected["kind"] == "device_approval"
    wire = json.dumps(projected).lower()
    for forbidden in ("selector", "target_ref", "binding", "envelope", "value"):
        assert forbidden not in wire


def test_project_native_auth_event_rejects_unknown_or_credential_fields():
    for payload in (
        {**_WIRE_COMPONENT, "value": "must-not-cross"},
        {**_WIRE_COMPONENT, "unexpected": {"nested": True}},
        {**_WIRE_COMPONENT, "binding": {**_WIRE_COMPONENT["binding"], "credential": "must-not-cross"}},
    ):
        with pytest.raises(NativeAuthRequestError):
            project_native_auth_event("native_component", payload)


def test_native_auth_route_lookup_recovers_unique_same_session_agent(monkeypatch):
    from api import config, routes

    agent = _Agent()
    monkeypatch.setitem(config.AGENT_INSTANCES, "stale-registry-key", agent)
    monkeypatch.setitem(config.STREAM_SESSION_OWNERS, "stream-1", "session-1")

    assert routes._native_auth_agent_lookup("stream-1") is agent


def test_native_auth_route_lookup_recovers_cached_agent_after_stream_teardown(monkeypatch):
    from api import config, routes

    agent = _Agent()
    monkeypatch.setitem(config.SESSION_AGENT_CACHE, "session-1", (agent, "cache-signature"))
    monkeypatch.setitem(config.STREAM_SESSION_OWNERS, "stream-1", "session-1")

    # The per-stream AGENT_INSTANCES entry is intentionally absent after normal
    # teardown; native auth must still reach the cached same-session runtime.
    assert "stream-1" not in config.AGENT_INSTANCES
    assert routes._native_auth_agent_lookup("stream-1") is agent


def test_native_auth_route_lookup_rejects_cached_identity_mismatch(monkeypatch):
    from api import config, routes

    class _WrongSessionAgent(_Agent):
        session_id = "session-2"

    agent = _WrongSessionAgent()
    monkeypatch.setitem(config.SESSION_AGENT_CACHE, "session-1", (agent, "cache-signature"))
    monkeypatch.setitem(config.STREAM_SESSION_OWNERS, "stream-1", "session-1")

    assert routes._native_auth_agent_lookup("stream-1") is None


class _RouteHandler:
    def __init__(self, *, client_ip="127.0.0.1", headers=None, body=b"{}"):
        self.client_address = (client_ip, 12345)
        self.headers = {"Content-Length": str(len(body)), **(headers or {})}
        self.rfile = BytesIO(body)
        self.wfile = BytesIO()
        self.status = None
        self.response_headers = []

    def send_response(self, status):
        self.status = status

    def send_header(self, name, value):
        self.response_headers.append((name, value))

    def end_headers(self):
        pass

    def json_body(self):
        return json.loads(self.wfile.getvalue())


@pytest.mark.parametrize("path", ["/api/native-auth/submit", "/api/native-auth/cancel"])
@pytest.mark.parametrize(
    ("client_ip", "headers"),
    [
        (
            "127.0.0.1",
            {"Host": "webui.example.test", "X-Semreh-Client": "native-auth-v1"},
        ),
        (
            "127.0.0.1",
            {
                "Host": "localhost:8787",
                "X-Semreh-Client": "native-auth-v1",
                "X-Forwarded-For": "127.0.0.1",
            },
        ),
        ("127.0.0.1", {"Host": "localhost:8787"}),
        (
            "192.0.2.10",
            {"Host": "localhost:8787", "X-Semreh-Client": "native-auth-v1"},
        ),
    ],
    ids=["public-host", "forwarded-client", "missing-native-header", "remote-peer"],
)
def test_passwordless_native_auth_rejects_before_body_or_runtime_lookup(
    monkeypatch, path, client_ip, headers
):
    from api import auth, routes

    body_reads = []
    runtime_lookups = []

    def fail_body_read(_handler):
        body_reads.append(True)
        raise AssertionError("body must not be read before native-auth authorization")

    def fail_runtime_lookup(stream_id):
        runtime_lookups.append(stream_id)
        raise AssertionError("runtime must not be looked up before native-auth authorization")

    monkeypatch.setattr(auth, "is_auth_enabled", lambda: False)
    monkeypatch.setattr(routes, "read_body", fail_body_read)
    monkeypatch.setattr(routes, "_native_auth_agent_lookup", fail_runtime_lookup)
    handler = _RouteHandler(client_ip=client_ip, headers=headers)

    routes.handle_post(handler, urlparse(path))

    assert handler.status == 403
    assert body_reads == []
    assert runtime_lookups == []


@pytest.mark.parametrize(
    ("client_ip", "host"),
    [
        ("127.0.0.1", "localhost:8787"),
        ("127.0.0.42", "127.0.0.1:8787"),
        ("::1", "[::1]:8787"),
        ("::ffff:127.0.0.1", "localhost"),
    ],
)
@pytest.mark.parametrize("path", ["/api/native-auth/submit", "/api/native-auth/cancel"])
def test_passwordless_native_auth_allows_only_direct_loopback_native_client(
    monkeypatch, client_ip, host, path
):
    from api import auth, routes

    monkeypatch.setattr(auth, "is_auth_enabled", lambda: False)
    handler = _RouteHandler(
        client_ip=client_ip,
        headers={"Host": host, "X-Semreh-Client": "native-auth-v1"},
    )

    assert routes._authorize_native_auth_mutation(handler, path) is True
    assert handler.status is None


@pytest.mark.parametrize("client_ip", ["10.0.0.5", "192.0.2.10", "2001:db8::10"])
def test_passwordless_native_auth_rejects_every_non_loopback_peer(
    monkeypatch, client_ip
):
    from api import auth, routes

    monkeypatch.setattr(auth, "is_auth_enabled", lambda: False)
    handler = _RouteHandler(
        client_ip=client_ip,
        headers={"Host": "localhost:8787", "X-Semreh-Client": "native-auth-v1"},
    )

    assert routes._authorize_native_auth_mutation(
        handler, "/api/native-auth/submit"
    ) is False
    assert handler.status == 403


@pytest.mark.parametrize(
    "host",
    [
        "webui.example.test",
        "192.0.2.10:8787",
        "[::1]not-an-authority",
        "[::1]:not-a-port",
        "localhost:70000",
    ],
)
def test_passwordless_native_auth_rejects_non_loopback_or_invalid_host_authority(
    monkeypatch, host
):
    from api import auth, routes

    monkeypatch.setattr(auth, "is_auth_enabled", lambda: False)
    handler = _RouteHandler(
        headers={"Host": host, "X-Semreh-Client": "native-auth-v1"}
    )

    assert routes._authorize_native_auth_mutation(
        handler, "/api/native-auth/submit"
    ) is False
    assert handler.status == 403


@pytest.mark.parametrize(
    ("header", "value"),
    [
        ("Forwarded", "for=127.0.0.1;host=localhost"),
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Real-IP", "127.0.0.1"),
    ],
)
def test_passwordless_native_auth_rejects_forwarded_client_headers(
    monkeypatch, header, value
):
    from api import auth, routes

    monkeypatch.setattr(auth, "is_auth_enabled", lambda: False)
    handler = _RouteHandler(
        headers={
            "Host": "127.0.0.1:8787",
            "X-Semreh-Client": "native-auth-v1",
            header: value,
        }
    )

    assert routes._authorize_native_auth_mutation(
        handler, "/api/native-auth/submit"
    ) is False
    assert handler.status == 403


@pytest.mark.parametrize(
    "value", [None, "", "native-auth-v2", " native-auth-v1", "native-auth-v1 "]
)
def test_passwordless_native_auth_rejects_missing_or_inexact_native_header(
    monkeypatch, value
):
    from api import auth, routes

    monkeypatch.setattr(auth, "is_auth_enabled", lambda: False)
    headers = {"Host": "localhost:8787"}
    if value is not None:
        headers["X-Semreh-Client"] = value
    handler = _RouteHandler(headers=headers)

    assert routes._authorize_native_auth_mutation(
        handler, "/api/native-auth/submit"
    ) is False
    assert handler.status == 403


def test_authenticated_native_auth_route_requires_visible_webui_session(monkeypatch):
    from api import auth, routes

    monkeypatch.setattr(auth, "is_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "parse_cookie", lambda _handler: None)
    handler = _RouteHandler()

    routes.handle_post(handler, urlparse("/api/native-auth/submit"))
    assert handler.status == 401


def test_authenticated_native_auth_route_requires_origin_and_csrf_provenance(monkeypatch):
    from api import auth, routes

    monkeypatch.setattr(auth, "is_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "parse_cookie", lambda _handler: "signed-session")
    monkeypatch.setattr(auth, "verify_session", lambda cookie: cookie == "signed-session")
    handler = _RouteHandler()

    routes.handle_post(handler, urlparse("/api/native-auth/submit"))
    assert handler.status == 403


@pytest.mark.parametrize("path", ["/api/native-auth/submit", "/api/native-auth/cancel"])
def test_authenticated_native_auth_route_accepts_exact_native_client_header(monkeypatch, path):
    from api import auth, routes

    monkeypatch.setattr(auth, "is_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "parse_cookie", lambda _handler: "signed-session")
    monkeypatch.setattr(auth, "verify_session", lambda cookie: cookie == "signed-session")
    handler = _RouteHandler(headers={"X-Semreh-Client": "native-auth-v1"})

    assert routes._authorize_native_auth_mutation(handler, path) is True
    assert handler.status is None


@pytest.mark.parametrize("value", ["", "native-auth-v2", " native-auth-v1", "native-auth-v1 "])
def test_authenticated_native_auth_route_rejects_missing_or_inexact_native_header(monkeypatch, value):
    from api import auth, routes

    monkeypatch.setattr(auth, "is_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "parse_cookie", lambda _handler: "signed-session")
    monkeypatch.setattr(auth, "verify_session", lambda cookie: cookie == "signed-session")
    headers = {"X-Semreh-Client": value} if value else {}
    handler = _RouteHandler(headers=headers)

    assert routes._authorize_native_auth_mutation(handler, "/api/native-auth/submit") is False
    assert handler.status == 403


def test_authenticated_native_auth_route_accepts_same_origin_browser(monkeypatch):
    from api import auth, routes

    monkeypatch.setattr(auth, "is_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "parse_cookie", lambda _handler: "signed-session")
    monkeypatch.setattr(auth, "verify_session", lambda cookie: cookie == "signed-session")
    handler = _RouteHandler(
        headers={
            "Host": "webui.example.test",
            "Origin": "https://webui.example.test",
            "Sec-Fetch-Site": "same-origin",
        }
    )

    assert routes._authorize_native_auth_mutation(handler, "/api/native-auth/submit") is True


def test_authenticated_native_auth_route_rejects_cross_origin_browser_even_with_native_header(monkeypatch):
    from api import auth, routes

    monkeypatch.setattr(auth, "is_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "parse_cookie", lambda _handler: "signed-session")
    monkeypatch.setattr(auth, "verify_session", lambda cookie: cookie == "signed-session")
    handler = _RouteHandler(
        headers={
            "Host": "webui.example.test",
            "Origin": "https://evil.example.test",
            "Sec-Fetch-Site": "cross-site",
            "X-Semreh-Client": "native-auth-v1",
        }
    )

    assert routes._authorize_native_auth_mutation(handler, "/api/native-auth/submit") is False
    assert handler.status == 403


def test_cors_preflight_does_not_allow_arbitrary_origin_or_native_client_header(monkeypatch):
    from api import routes

    monkeypatch.setattr(routes, "_allowed_public_origins", lambda: set())
    handler = _RouteHandler(
        headers={
            "Host": "webui.example.test",
            "Origin": "https://evil.example.test",
            "Access-Control-Request-Headers": "x-semreh-client",
        }
    )

    routes.apply_cors_preflight_headers(handler)

    assert not any(name.lower().startswith("access-control-allow") for name, _ in handler.response_headers)


def test_native_auth_runtime_failure_is_typed_opaque_and_maps_to_503(monkeypatch):
    from api import auth, routes

    class _FailingAgent(_Agent):
        def submit_native_auth_envelope(self, envelope):
            raise RuntimeError("selector=input[type=password] ciphertext=must-not-cross")

    body = json.dumps(
        {"session_id": "session-1", "stream_id": "stream-1", "envelope": _WIRE_ENVELOPE}
    ).encode()
    monkeypatch.setattr(auth, "is_auth_enabled", lambda: False)
    monkeypatch.setattr(routes, "_native_auth_agent_lookup", lambda _stream_id: _FailingAgent())
    monkeypatch.setattr(routes, "_guard_request_session_visibility", lambda *args, **kwargs: True)
    handler = _RouteHandler(
        body=body,
        headers={"Host": "localhost:8787", "X-Semreh-Client": "native-auth-v1"},
    )

    routes.handle_post(handler, urlparse("/api/native-auth/submit"))

    assert handler.status == 503
    assert handler.json_body() == {
        "ok": False,
        "state": "transient_runtime",
        "code": "transient_runtime",
        "stage": "runtime",
        "retryable": True,
        "requires_remint": False,
    }
    assert "must-not-cross" not in handler.wfile.getvalue().decode()


@pytest.mark.parametrize(
    ("message", "status", "code", "stage", "retryable", "requires_remint"),
    [
        ("native auth envelope replay", 409, "replay", "validate", False, True),
        ("auth component belongs to another session", 409, "owner_mismatch", "ownership", False, False),
        ("auth component expired", 410, "expired", "validate", False, True),
        ("auth component is no longer active", 410, "context_lost", "ownership", False, True),
        ("secure browser target changed after navigation", 422, "target_changed", "preflight", False, True),
        ("secure browser target adapter unavailable", 422, "unsupported", "preflight", False, False),
        ("native auth operation busy", 409, "busy", "runtime", True, False),
    ],
)
def test_native_auth_runtime_messages_map_to_closed_opaque_outcomes(
    message, status, code, stage, retryable, requires_remint
):
    class _RejectedAgent(_Agent):
        def submit_native_auth_envelope(self, envelope):
            raise RuntimeError(message)

    with pytest.raises(NativeAuthRequestError) as raised:
        submit_native_auth_request(
            {"session_id": "session-1", "stream_id": "stream-1", "envelope": _WIRE_ENVELOPE},
            agent_lookup=lambda _stream_id: _RejectedAgent(),
        )

    assert raised.value.status == status
    assert raised.value.public_payload() == {
        "ok": False,
        "state": code,
        "code": code,
        "stage": stage,
        "retryable": retryable,
        "requires_remint": requires_remint,
    }
    assert message not in json.dumps(raised.value.public_payload())


def test_native_auth_success_returns_closed_terminal_outcome():
    payload = submit_native_auth_request(
        {"session_id": "session-1", "stream_id": "stream-1", "envelope": _WIRE_ENVELOPE},
        agent_lookup=lambda _stream_id: _Agent(),
    )

    assert payload == {
        "ok": True,
        "state": "submitted",
        "code": "submitted",
        "stage": "complete",
        "retryable": False,
        "requires_remint": False,
    }


@pytest.mark.parametrize(
    ("state", "status", "code"),
    [
        ("expired", 410, "expired"),
        ("failed", 409, "rejected"),
        ("accepted", 503, "transient_runtime"),
        ("filled", 503, "transient_runtime"),
    ],
)
def test_native_auth_nonterminal_or_failed_runtime_states_map_deterministically(state, status, code):
    class _StateAgent(_Agent):
        def submit_native_auth_envelope(self, envelope):
            return {"state": state, "debug": "must-not-cross"}

    with pytest.raises(NativeAuthRequestError) as raised:
        submit_native_auth_request(
            {"session_id": "session-1", "stream_id": "stream-1", "envelope": _WIRE_ENVELOPE},
            agent_lookup=lambda _stream_id: _StateAgent(),
        )

    assert raised.value.status == status
    assert raised.value.code == code
    assert raised.value.public_payload()["state"] == code
    assert "must-not-cross" not in json.dumps(raised.value.public_payload())


@pytest.mark.parametrize(
    ("state", "status", "code"),
    [
        ("cancelled", 200, "cancelled"),
        ("expired", 410, "expired"),
        ("failed", 409, "rejected"),
        ("accepted", 503, "transient_runtime"),
        ("filled", 503, "transient_runtime"),
    ],
)
def test_native_auth_cancel_runtime_states_use_same_typed_outcome_taxonomy(state, status, code):
    class _CancelStateAgent(_Agent):
        def cancel_native_component(self, component_id):
            return {"state": state, "component_id": component_id, "debug": "must-not-cross"}

    if status == 200:
        payload = cancel_native_auth_request(
            {"session_id": "session-1", "stream_id": "stream-1", "component_id": "cmp_12345678"},
            agent_lookup=lambda _stream_id: _CancelStateAgent(),
        )
        assert payload == {
            "ok": True,
            "state": "cancelled",
            "code": "cancelled",
            "stage": "cancel",
            "retryable": False,
            "requires_remint": False,
        }
        return

    with pytest.raises(NativeAuthRequestError) as raised:
        cancel_native_auth_request(
            {"session_id": "session-1", "stream_id": "stream-1", "component_id": "cmp_12345678"},
            agent_lookup=lambda _stream_id: _CancelStateAgent(),
        )
    assert raised.value.status == status
    assert raised.value.code == code
    assert raised.value.public_payload()["state"] == code
    assert "must-not-cross" not in json.dumps(raised.value.public_payload())


def test_native_auth_cancel_runtime_exception_is_typed_and_opaque():
    class _FailingCancelAgent(_Agent):
        def cancel_native_component(self, component_id):
            raise RuntimeError("selector=#password ciphertext=must-not-cross")

    with pytest.raises(NativeAuthRequestError) as raised:
        cancel_native_auth_request(
            {"session_id": "session-1", "stream_id": "stream-1", "component_id": "cmp_12345678"},
            agent_lookup=lambda _stream_id: _FailingCancelAgent(),
        )
    assert raised.value.status == 503
    assert raised.value.public_payload() == {
        "ok": False,
        "state": "transient_runtime",
        "code": "transient_runtime",
        "stage": "runtime",
        "retryable": True,
        "requires_remint": False,
    }


def test_native_auth_cancel_route_preserves_typed_http_status(monkeypatch):
    from api import auth, routes

    class _ExpiredCancelAgent(_Agent):
        def cancel_native_component(self, component_id):
            return {"state": "expired", "component_id": component_id}

    body = json.dumps(
        {"session_id": "session-1", "stream_id": "stream-1", "component_id": "cmp_12345678"}
    ).encode()
    monkeypatch.setattr(auth, "is_auth_enabled", lambda: False)
    monkeypatch.setattr(routes, "_native_auth_agent_lookup", lambda _stream_id: _ExpiredCancelAgent())
    monkeypatch.setattr(routes, "_guard_request_session_visibility", lambda *args, **kwargs: True)
    handler = _RouteHandler(
        body=body,
        headers={"Host": "localhost:8787", "X-Semreh-Client": "native-auth-v1"},
    )

    routes.handle_post(handler, urlparse("/api/native-auth/cancel"))

    assert handler.status == 410
    assert handler.json_body() == {
        "ok": False,
        "state": "expired",
        "code": "expired",
        "stage": "validate",
        "retryable": False,
        "requires_remint": True,
    }


class _FakeNativeRuntime:
    def __init__(self):
        self.registered = []
        self.closed = []

    def register_component_callback(self, task_id, callback):
        self.registered.append((task_id, callback))

    def close_task(self, task_id):
        self.closed.append(task_id)
        return 1


def test_native_auth_task_lifecycle_binds_and_closes_without_identifiers_in_diagnostics():
    runtime = _FakeNativeRuntime()
    callback = lambda _component: None

    bind_native_auth_task("session-private-123", callback, runtime=runtime)
    cleaned = close_native_auth_task("session-private-123", runtime=runtime)
    snapshot = native_auth_diagnostics_snapshot()

    assert runtime.registered == [("session-private-123", callback)]
    assert runtime.closed == ["session-private-123"]
    assert cleaned == 1
    assert "session-private-123" not in json.dumps(snapshot)
    assert set(snapshot) == {"bound_tasks", "counters"}


def test_native_auth_shutdown_cleanup_closes_every_bound_task():
    runtime = _FakeNativeRuntime()
    bind_native_auth_task("session-shutdown-a", lambda _: None, runtime=runtime)
    bind_native_auth_task("session-shutdown-b", lambda _: None, runtime=runtime)

    cleaned = close_all_native_auth_tasks(runtime=runtime)

    assert cleaned == 2
    assert set(runtime.closed) == {"session-shutdown-a", "session-shutdown-b"}
    assert native_auth_diagnostics_snapshot()["bound_tasks"] == 0


def test_config_agent_eviction_closes_native_auth_task_even_without_cached_agent(monkeypatch):
    from api import config, native_auth

    closed = []
    monkeypatch.setattr(native_auth, "close_native_auth_task", lambda session_id: closed.append(session_id))
    with config.SESSION_AGENT_CACHE_LOCK:
        config.SESSION_AGENT_CACHE.pop("session-evicted", None)

    config._evict_session_agent("session-evicted")

    assert closed == ["session-evicted"]


def test_streaming_lru_agent_eviction_closes_native_auth_task(monkeypatch):
    from api import native_auth, streaming

    closed = []
    monkeypatch.setattr(native_auth, "close_native_auth_task", lambda session_id: closed.append(session_id))
    monkeypatch.setattr(streaming, "_lifecycle_commit_session_memory", lambda *args, **kwargs: None)
    monkeypatch.setattr(streaming, "_lifecycle_has_uncommitted_work", lambda _session_id: False)
    monkeypatch.setattr(streaming, "_lifecycle_unregister_agent", lambda _session_id: None)
    monkeypatch.setattr(streaming, "_lifecycle_discard_session", lambda _session_id: True)

    assert streaming._close_evicted_agent_at_session_boundary("session-lru-evicted", object()) is True
    assert closed == ["session-lru-evicted"]


@pytest.mark.parametrize("terminal_state", ["submitted", "failed", "cancelled", "expired"])
def test_every_terminal_native_auth_status_detaches_task_callback(monkeypatch, terminal_state):
    from api import streaming

    runtime = _FakeNativeRuntime()
    runtime.set_status_callback = lambda _component_id, callback: setattr(runtime, "status_callback", callback)
    runtime.public_components = lambda _component_id: [_WIRE_COMPONENT]
    runtime.public_state = lambda _component_id, **kwargs: {
        "type": "semreh.native-component-state.v1",
        "issued_by": "browser",
        "immutable": True,
        "context_id": "ctx_12345678",
        "browser_session_id": "bs_12345678",
        "component_id": "cmp_12345678",
        "action_handle": "act_12345678",
        "kind": "secret",
        "provider_origin": "https://accounts.example.test",
        "path": "/login",
        "status": kwargs["state"],
        **({"cancel_reason": kwargs["cancel_reason"]} if kwargs.get("cancel_reason") else {}),
    }
    monkeypatch.setattr(streaming, "update_active_run", lambda *args, **kwargs: None)

    assert streaming._bind_native_auth_component(
        {"component_id": "ctx_12345678"},
        session_id="session-terminal",
        stream_id="stream-terminal",
        put=lambda *_args: None,
        runtime=runtime,
    ) is True
    runtime.status_callback({"state": terminal_state})

    assert runtime.registered[-1] == ("session-terminal", None)


def test_terminal_native_auth_status_closes_task_but_stream_teardown_alone_does_not(monkeypatch):
    from api import streaming

    runtime = _FakeNativeRuntime()
    runtime.states = []

    def set_status_callback(component_id, callback):
        runtime.status_callback = callback

    runtime.set_status_callback = set_status_callback
    runtime.public_components = lambda _component_id: [{**_WIRE_COMPONENT, "binding": _WIRE_COMPONENT["binding"]}]
    runtime.public_state = lambda _component_id, **kwargs: {
        "type": "semreh.native-component-state.v1",
        "issued_by": "browser",
        "immutable": True,
        "context_id": "ctx_12345678",
        "browser_session_id": "bs_12345678",
        "component_id": "cmp_12345678",
        "action_handle": "act_12345678",
        "kind": "secret",
        "provider_origin": "https://accounts.example.test",
        "path": "/login",
        "status": kwargs["state"],
        **({"cancel_reason": kwargs["cancel_reason"]} if kwargs.get("cancel_reason") else {}),
    }
    emitted = []
    monkeypatch.setattr(streaming, "update_active_run", lambda *args, **kwargs: None)

    assert streaming._bind_native_auth_component(
        {"component_id": "ctx_12345678"},
        session_id="session-stream-recovery",
        stream_id="stream-1",
        put=lambda event, payload: emitted.append((event, payload)),
        runtime=runtime,
    ) is True
    assert runtime.closed == []

    runtime.status_callback({"state": "submitted"})

    assert runtime.closed == []
    assert runtime.registered[-1] == ("session-stream-recovery", None)
    assert emitted[-1][0] == "native_component_state"


def test_initial_native_auth_state_is_published_after_components(monkeypatch):
    from api import streaming

    runtime = _FakeNativeRuntime()
    runtime.set_status_callback = lambda _component_id, callback: setattr(
        runtime, "status_callback", callback
    )
    runtime.public_components = lambda _component_id: [
        {**_WIRE_COMPONENT, "component_id": "cmp_input_12345678"},
        {**_WIRE_COMPONENT, "component_id": "cmp_submit_12345678", "kind": "submit"},
    ]
    runtime.public_state = lambda _component_id, **kwargs: {
        "type": "semreh.native-component-state.v1",
        "issued_by": "browser",
        "immutable": True,
        "context_id": "ctx_12345678",
        "browser_session_id": "bs_12345678",
        "component_id": "cmp_submit_12345678",
        "action_handle": "act_12345678",
        "kind": "submit",
        "provider_origin": "https://accounts.example.test",
        "path": "/login",
        "status": kwargs["state"],
    }
    emitted = []
    monkeypatch.setattr(streaming, "update_active_run", lambda *args, **kwargs: None)

    assert streaming._bind_native_auth_component(
        {"component_id": "ctx_12345678"},
        session_id="session-initial-order",
        stream_id="stream-initial-order",
        put=lambda event, payload: emitted.append((event, payload)),
        runtime=runtime,
    ) is True

    assert [event for event, _payload in emitted] == [
        "native_component",
        "native_component",
        "native_component_state",
    ]
    assert emitted[-1][1]["status"] == "available"
