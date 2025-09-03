# Test suite for FastAPI application.
# Framework: pytest + starlette.testclient.TestClient

import os
import threading
from contextlib import contextmanager
from unittest.mock import patch, MagicMock

import pytest

try:
    # Prefer FastAPI/Starlette TestClient already used in repo

    from fastapi.testclient import TestClient
except ImportError:  # Fallback to starlette if fastapi import path differs
    from starlette.testclient import TestClient  # type: ignore

# Import the application module
# Adjust this import if your app module is not named 'main'
import main


@contextmanager
def set_env(var, value):
    old = os.environ.get(var)
    if value is None:
        os.environ.pop(var, None)
    else:
        os.environ[var] = value
    try:
        yield
    finally:
        if old is None:
            os.environ.pop(var, None)
        else:
            os.environ[var] = old


class DummyWorker:
    started = threading.Event()

    @staticmethod
    def run():
        # mark that the worker target was invoked
        DummyWorker.started.set()


@pytest.mark.parametrize(
    "env_value, expected",
    [
        (None, 1),            # default
        ("", 1),              # empty -> int("") raises -> fallback to 1
        ("abc", 1),           # non-int -> fallback to 1
        ("0", 1),             # below min -> coerced to 1
        ("-5", 1),            # negative -> coerced to 1
        ("2", 2),             # normal small value
        ("1000", 64),         # above cap -> capped to 64
    ],
)
def test_worker_lifespan_thread_count(monkeypatch, env_value, expected):
    # Monkeypatch the worker_loop symbol to a harmless function
    monkeypatch.setattr(main, "worker_loop", DummyWorker.run, raising=True)

    with set_env("WORKER_COUNT", env_value):
        # Instantiate a fresh app bound to worker_lifespan to avoid state carry-over
        app = main.FastAPI(lifespan=main.worker_lifespan)
        with TestClient(app):
            # Trigger startup; verify worker_threads created and sized correctly
            threads = getattr(app.state, "worker_threads", [])
            assert isinstance(threads, list)  # noqa: S101
            assert len(threads) == expected  # noqa: S101
            # Daemonized and named properly
            for idx, th in enumerate(threads, start=1):
                assert th.daemon is True  # noqa: S101
                assert th.is_alive()  # threads should have been started  # noqa: S101
                assert th.name.startswith("Worker-")  # noqa: S101
                # exact naming check for first and last where deterministic
                if idx in (1, expected):
                    assert th.name == f"Worker-{idx}"  # noqa: S101


def test_worker_lifespan_app_state_persists_threads(monkeypatch):
    monkeypatch.setattr(main, "worker_loop", DummyWorker.run, raising=True)
    with TestClient(main.app):
        threads = getattr(main.app.state, "worker_threads", None)
        assert threads is not None and len(threads) >= 1  # noqa: S101


def test_cors_middleware_allows_specific_origin(monkeypatch):
    # Use monkeypatch variable to avoid unused-argument lint warning
    _ = monkeypatch
    # Validate CORSMiddleware configuration from diff (allow_origins=["http://localhost:3000"])
    with TestClient(main.app) as client:
        resp = client.options(
            "/",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
            },
        )
        # CORS preflight should succeed with 200/204 and include ACAO header
        assert resp.status_code in (200, 204)  # noqa: S101
        assert resp.headers.get("access-control-allow-origin") == "http://localhost:3000"  # noqa: S101


def test_send_escalation_email_success_path():
    # Function returns deterministic message concatenation per diff
    result = main.send_escalation_email("Subj", "Body", "to@example.com")
    assert result == "Email sent successfully ." + "Body"  # noqa: S101


@pytest.mark.parametrize(
    "status_text, expected_action_contains",
    [
        ("stopped", "Attempting to start it."),
        ("running", "Instance has been started successfully."),
        ("unknown", "status is unknown"),
    ],
)
def test_power_status_tool_branches(monkeypatch, tmp_path, status_text, expected_action_contains):
    # Mock external dependencies extensively
    fake_model = MagicMock()
    # generate_content returns an object with .parts[0].text
    def gc_side_effect(prompt):
        class Part:
            def __init__(self, t): self.text = t
        class Resp:
            def __init__(self, t): self.parts = [Part(t)]
        # Route prompts to status/os/ip
        if "status and OS information" in prompt and "os and flavour" not in prompt:
            return Resp(status_text)
        if "os and flavour" in prompt:
            return Resp("ubuntu")
        if "public ipv4" in prompt:
            return Resp("203.0.113.10")
        return Resp("running")
    fake_model.generate_content.side_effect = gc_side_effect

    monkeypatch.setattr(main.genai, "GenerativeModel", lambda *_args, **_kw: fake_model)

    # Mock requests.get for playbook
    monkeypatch.setattr(main.requests, "get", lambda *args, **kwargs: type("R", (), {"text": "---"})())

    # Mock boto3 client
    fake_ec2 = MagicMock()
    monkeypatch.setattr(main, "boto3", MagicMock(client=lambda *args, **kwargs: fake_ec2))

    # Ensure file reads
    assets_path = tmp_path / "aws_assets.json"
    assets_path.write_text('{"Instances": []}')
    # Patch open paths within module working dir by chdir context
    cwd = os.getcwd()
    os.chdir(tmp_path)

    # Prevent subprocess.run side effects
    monkeypatch.setattr(main.subprocess, "run", lambda *args, **kwargs: None)
    # Prevent os.remove raising if file missing
    monkeypatch.setattr(main.os, "remove", lambda *args, **kwargs: None)

    # Stub escalation email to avoid prints
    monkeypatch.setattr(main, "send_escalation_email", lambda *args, **kwargs: "sent")

    Aws = {
        "access_key": "AKIA...",
        "secrete_access": "SECRET",
        "region": "us-east-1",
        "instance_id": "i-1234567890abcdef0",
    }
    try:
        out = main.power_status_tool(Aws)
    finally:
        os.chdir(cwd)

    assert "status_and_os_info" in out  # noqa: S101
    assert out["ipv4"].startswith("203.0.113.")  # noqa: S101
    assert "os" in out and out["os"] == "ubuntu"  # noqa: S101
    assert expected_action_contains in out["action"]  # noqa: S101

    if "stopped" in status_text:
        fake_ec2.start_instances.assert_called_once()
    else:
        fake_ec2.start_instances.assert_not_called()


def test_execute_command_happy_path(monkeypatch):
    # Mock key dependencies: genai, paramiko, supabase, send_mail_to_l2_engineer
    fake_model = MagicMock()
    fake_model.generate_content.side_effect = [
        # command1
        type("R", (), {"parts": [type("P", (), {"text": "echo hello"})()]})(),
        # result1 (resolution verdict)
        type("R", (), {"parts": [type("P", (), {"text": "resolved"})()]})(),
    ]
    monkeypatch.setattr(main.genai, "GenerativeModel", lambda *_a, **_k: fake_model)

    # Mock redis r.get('userjwt') call via monkeypatch if present; fallback no-op
    if hasattr(main, "r"):
        monkeypatch.setattr(main.r, "get", lambda *args, **kwargs: "jwt")

    # Mock SSH
    fake_ssh = MagicMock()
    fake_stdout = MagicMock()
    fake_stderr = MagicMock()
    fake_stdout.read.return_value = b"ok"
    fake_stderr.read.return_value = b""
    fake_ssh.exec_command.return_value = (None, fake_stdout, fake_stderr)

    class FakeSSHClient:
        def set_missing_host_key_policy(self, *_): pass
        def connect(self, *_, **__): pass
        def exec_command(self, *args, **kwargs): return fake_ssh.exec_command(*args, **kwargs)
        def close(self): pass

    monkeypatch.setattr(main.paramiko, "SSHClient", lambda: FakeSSHClient())
    monkeypatch.setattr(main.paramiko, "AutoAddPolicy", lambda: object())

    # Mock file removal
    monkeypatch.setattr(main.os, "remove", lambda *args, **kwargs: None)

    # Mock supabase
    fake_table_results = MagicMock()
    fake_table_results.execute.return_value = {"status": "ok"}
    fake_supabase = MagicMock()
    fake_supabase.table.return_value = MagicMock(
        update=lambda *_a, **_k: MagicMock(eq=lambda *_a, **_k: fake_table_results),
        insert=lambda *_a, **_k: MagicMock(execute=lambda: {"status": "ok"}),
    )
    monkeypatch.setattr(main, "supabase", fake_supabase)

    res = main.execute_command(
        command="check cpu",
        hostname="203.0.113.10",
        username="ubuntu",
        incident="cpu high",
        inc_number="INC123",
    )

    assert res["output"] == "ok"  # noqa: S101
    assert res["error"] == ""  # noqa: S101
    assert "resolved" in res["result"].lower()  # noqa: S101


def test_execute_command_unresolved_sends_email(monkeypatch):
    fake_model = MagicMock()
    fake_model.generate_content.side_effect = [
        type("R", (), {"parts": [type("P", (), {"text": "echo fail"})()]})(),
        type("R", (), {"parts": [type("P", (), {"text": "not resolved"})()]})(),
    ]
    monkeypatch.setattr(main.genai, "GenerativeModel", lambda *_a, **_k: fake_model)

    # SSH mocks
    class SSH:
        def set_missing_host_key_policy(self, *_): pass
        def connect(self, *_, **__): pass
        def exec_command(self, *_a, **_k):
            class R:
                def read(self):
                    return b"out" if _a and "echo" in _a[0] else b""
            return (None, R(), R())
        def close(self): pass

    monkeypatch.setattr(main.paramiko, "SSHClient", lambda: SSH())
    monkeypatch.setattr(main.paramiko, "AutoAddPolicy", lambda: object())
    monkeypatch.setattr(main.os, "remove", lambda *args, **kwargs: None)

    emailed = {}
    def fake_mail(*args, **kwargs):
        emailed["called"] = True
    monkeypatch.setattr(main, "send_mail_to_l2_engineer", fake_mail)

    res = main.execute_command(
        command="check disk",
        hostname="198.51.100.5",
        username="ec2-user",
        incident="disk high",
        inc_number="INC999",
    )
    assert res["result"] == "Email sent to L2 engineer"  # noqa: S101
    assert emailed.get("called", False) is True  # noqa: S101


@pytest.mark.anyio
async def test_verify_token_success(monkeypatch):
    # Mock jwt.decode -> payload with email
    monkeypatch.setattr(main, "jwt", MagicMock(decode=lambda *args, **kwargs: {"email": "user@example.com"}))
    # Mock supabase user lookup
    fake_execute = MagicMock()
    fake_execute.data = [{"id": "user-123"}]
    fake_table = MagicMock(select=lambda *_a, **_k: MagicMock(eq=lambda *_a, **_k: fake_execute))
    monkeypatch.setattr(main, "supabase", MagicMock(table=lambda *_a, **_k: fake_table))

    # Build fake credentials object
    class Cred:
        def __init__(self, c): self.credentials = c

    res = await main.verify_token(Cred("token"))
    assert res == {"email": "user@example.com", "user_id": "user-123"}  # noqa: S101


@pytest.mark.anyio
async def test_verify_token_invalid_token(monkeypatch):
    class Err(Exception):
        pass
    monkeypatch.setattr(main, "PyJWTError", Err)
    def raiser(*_a, **_k): raise Err("bad")
    monkeypatch.setattr(main, "jwt", MagicMock(decode=raiser))

    class Cred:
        def __init__(self, c): self.credentials = c

    with pytest.raises(main.HTTPException) as ei:
        await main.verify_token(Cred("bad-token"))
    assert ei.value.status_code == 401  # noqa: S101
    assert "invalid token" in ei.value.detail  # noqa: S101


@pytest.mark.anyio
async def test_cmdb_create_conflict_and_success(monkeypatch):
    # Token verification dependency result
    user_data = {"email": "u@e.com", "user_id": "uid-1"}

    # Mock supabase workflow for existing and insert
    existing_resp = MagicMock()
    existing_resp.data = [{"tag_id": "tag1"}]

    insert_resp = MagicMock()
    insert_resp.data = [{"id": 1}]

    def table(*_args, **_kwargs):
        class T:
            def select(self, *_a, **_k):
                class Q:
                    def eq(self, *_a, **_k): return existing_resp
                return Q()
            def insert(self, *args, **kwargs):
                class E:
                    def execute(self): return insert_resp
                return E()
        return T()

    monkeypatch.setattr(main, "supabase", MagicMock(table=table))

    # Conflict path
    with pytest.raises(main.HTTPException) as ei:
        await main.create_cmdb_item(main.CMDBItem(tag_id="tag1", ip="192.0.2.10", addr="srv", type="vm", description="d"), user_data=user_data)
    assert ei.value.status_code == 409  # noqa: S101

    # Switch existing to empty for success path
    existing_resp.data = []
    out = await main.create_cmdb_item(main.CMDBItem(tag_id="tag1", ip="192.0.2.10", addr="srv", type="vm", description="d"), user_data=user_data)
    assert "response" in out  # noqa: S101


@pytest.mark.anyio
async def test_cmdb_get_and_not_found(monkeypatch):
    user_data = {"user_id": "uid-1"}
    resp = MagicMock()
    resp.data = []
    fake_table = MagicMock(select=lambda *_a, **_k: MagicMock(eq=lambda *_a, **_k: resp))
    monkeypatch.setattr(main, "supabase", MagicMock(table=lambda *_a, **_k: fake_table))

    with pytest.raises(main.HTTPException) as ei:
        await main.get_cmdb_item("nope", user_data=user_data)
    assert ei.value.status_code == 404  # noqa: S101

    resp.data = [{"tag_id": "ok"}]
    out = await main.get_cmdb_item("ok", user_data=user_data)
    assert "response" in out  # noqa: S101


@pytest.mark.anyio
async def test_cmdb_update_builds_update_dict(monkeypatch):
    user_data = {"user_id": "uid-1"}
    existing = MagicMock()
    existing.data = [{"tag_id": "t"}]
    update_exec = MagicMock()
    fake_table = MagicMock(
        select=lambda *_a, **_k: MagicMock(eq=lambda *_a, **_k: existing),
        update=lambda *args, **kwargs: MagicMock(eq=lambda *_a, **_k: update_exec),
    )
    monkeypatch.setattr(main, "supabase", MagicMock(table=lambda *_a, **_k: fake_table))

    item = main.CMDBItemUpdate(tag_id="t2", ip="198.51.100.1", addr="a", type="vm", description="d", os="ubuntu")
    out = await main.update_cmdb_item("t", item, user_data=user_data)
    assert "response" in out  # noqa: S101


@pytest.mark.anyio
async def test_cmdb_delete_requires_ownership(monkeypatch):
    user_data = {"user_id": "uid-1"}
    existing = MagicMock()
    existing.data = []
    fake_table = MagicMock(select=lambda *_a, **_k: MagicMock(eq=lambda *_a, **_k: existing))
    monkeypatch.setattr(main, "supabase", MagicMock(table=lambda *_a, **_k: fake_table))

    with pytest.raises(main.HTTPException) as ei:
        await main.delete_cmdb_item("t", user_data=user_data)
    assert ei.value.status_code == 404  # noqa: S101


def test_queue_add_builds_message(monkeypatch):
    # Patch boto3 session resource chain
    fake_queue = MagicMock(send_message=lambda *args, **kwargs: {"MessageId": "mid"})
    fake_sqs = MagicMock(get_queue_by_name=lambda *args, **kwargs: fake_queue)
    fake_session = MagicMock(resource=lambda *args, **kwargs: fake_sqs)
    monkeypatch.setattr(main, "session", fake_session)

    s_secret = "s"
    req = main.RequestBody(
        Aws=main.Aws(access_key="a", secrete_access=s_secret, region="r", instance_id="i"),
        Mail=main.IncidentMail(inc_number="INC1", subject="s", message="m"),
    )
    main.queueAdd(req)
    # Function returns None in diff; but ensure no exception and our mocks were called
    fake_queue.send_message.assert_called_once()