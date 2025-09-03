# ruff: noqa
import os
import json
import types
import tempfile
from pathlib import Path
from unittest import mock

import pytest  # Prefer pytest if available; tests also run under plain unittest with pytest skipped markers ignored.

# Attempt to import the module under test. It might live as 'handler.py' or within a package.
# We try common locations; if import fails, tests will be skipped with a helpful message.
MODULE_IMPORT_ERR = None
handler = None
for cand in ("handler", "src.handler", "app.handler", "lambda_function"):
    try:
        handler = __import__(cand, fromlist=["*"])
        break
    except Exception as e:  # pragma: no cover - import probing path
        MODULE_IMPORT_ERR = e

pytestmark = pytest.mark.skipif(
    handler is None, reason=f"Could not import handler module: {MODULE_IMPORT_ERR}"
)

@pytest.fixture(autouse=True)
def env_setup(monkeypatch):
    # Ensure deterministic environment for bucket and region
    monkeypatch.setenv("ANSIBLE_RUNTIME_BUCKET", "test-bucket")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)

def _fake_s3(pages):
    """
    Build a fake s3 client with:
      - get_paginator('list_objects_v2') yielding provided pages
      - download_file collecting calls
      - put_object capturing payload
    """
    calls = {"download": [], "put": []}

    class Paginator:
        def paginate(self, Bucket, _prefix):
            assert Bucket == "test-bucket"
            # Prefix is validated by caller; just yield supplied pages
            for p in pages:
                yield p

    class FakeS3:
        def __init__(self):
            self._paginator = Paginator()

        def get_paginator(self, name):
            assert name == "list_objects_v2"
            return self._paginator

        def download_file(self, bucket, key, dst):
            assert bucket == "test-bucket"
            calls["download"].append((key, dst))
            # Simulate presence of a downloaded file by touching it
            Path(dst).parent.mkdir(parents=True, exist_ok=True)
            Path(dst).write_text("content")

        def put_object(self, Bucket, Key, Body):
            assert Bucket == "test-bucket"
            calls["put"].append((Key, Body))

    return FakeS3(), calls

@pytest.fixture
def reload_handler_with_s3(monkeypatch):
    """
    Helper to reload the handler module after patching boto3.client so
    module-level s3 = boto3.client(...) captures our fake in import time.
    """
    import importlib

    def _reload(fake_s3_client):
        # Patch boto3.client before import/reload
        import boto3
        monkeypatch.setattr(boto3, "client", lambda *_, **__: fake_s3_client, raising=True)
        # If already imported, reload to rebind the module-level s3
        global handler
        if handler is not None:
            handler = importlib.reload(handler)
        return handler

    return _reload

def test__chmod_if_exists_sets_executable_when_present(tmp_path, reload_handler_with_s3):
    fake_s3, _ = _fake_s3(pages=[])
    mod = reload_handler_with_s3(fake_s3)

    f = tmp_path / "script.sh"
    f.write_text("#!/bin/bash\necho hi\n")
    # Initially non-executable
    os.chmod(f, 0o644)
    mod._chmod_if_exists(str(f))
    st = f.stat()
    assert (st.st_mode & 0o777) == 0o755

def test__chmod_if_exists_noop_when_missing(tmp_path, reload_handler_with_s3):
    fake_s3, _ = _fake_s3(pages=[])
    mod = reload_handler_with_s3(fake_s3)
    missing = tmp_path / "nope.sh"
    # Should not raise
    mod._chmod_if_exists(str(missing))
    assert not missing.exists()

def test__download_prefix_downloads_files_and_creates_dirs(tmp_path, reload_handler_with_s3):
    pages = [
        {"Contents": [{"Key": "pref/"}, {"Key": "pref/a/b.txt"}, {"Key": "pref/c.txt"}]},
        {"Contents": [{"Key": "pref/a/d/e.bin"}]},
    ]
    fake_s3, calls = _fake_s3(pages=pages)
    mod = reload_handler_with_s3(fake_s3)

    mod._download_prefix("pref/", str(tmp_path))

    # Verify download calls and created files
    keys = [k for (k, _) in calls["download"]]
    assert keys == ["pref/a/b.txt", "pref/c.txt", "pref/a/d/e.bin"]
    # Leading prefix object 'pref/' was skipped
    assert all(Path(dst).exists() for (_, dst) in calls["download"])
    assert (tmp_path / "a").is_dir()
    assert (tmp_path / "a" / "b.txt").is_file()
    assert (tmp_path / "c.txt").is_file()

def test__download_prefix_handles_empty_pages(tmp_path, reload_handler_with_s3):
    fake_s3, calls = _fake_s3(pages=[{}, {"Contents": []}])
    mod = reload_handler_with_s3(fake_s3)

    mod._download_prefix("prefix/", str(tmp_path))
    assert calls["download"] == []  # no downloads

def test__run_scripts_executes_and_captures_outputs(tmp_path, reload_handler_with_s3):
    fake_s3, _ = _fake_s3(pages=[])
    mod = reload_handler_with_s3(fake_s3)

    # Create scripts
    (tmp_path / "install_ansible_modules.sh").write_text('echo "install ok"; exit 0')
    (tmp_path / "playbook_command.sh").write_text('echo "play ok"; echo "warn" 1>&2; exit 3')

    # Use real subprocess to run tiny echo scripts safely
    res = mod._run_scripts(str(tmp_path))
    assert res["install_rc"] == 0
    assert "install ok" in res["install_out"]
    assert res["install_err"] == ""
    assert res["play_rc"] == 3
    assert "play ok" in res["play_out"]
    assert "warn" in res["play_err"]

def test__run_scripts_uses_chmod_if_exists(tmp_path, reload_handler_with_s3):
    fake_s3, _ = _fake_s3(pages=[])
    mod = reload_handler_with_s3(fake_s3)

    # Create only one script to ensure chmod handles both present/absent without raising
    (tmp_path / "install_ansible_modules.sh").write_text('exit 0')
    # Spy on chmod to ensure it's called twice (install and playbook)
    with mock.patch.object(mod, "_chmod_if_exists") as spy:
        # Patch subprocess to avoid executing when one script is missing
        cp_ok = types.SimpleNamespace(returncode=0, stdout="", stderr="")
        cp_fail = types.SimpleNamespace(returncode=127, stdout="", stderr="not found")
        with mock.patch("subprocess.run", side_effect=[cp_ok, cp_fail]) as run_mock:
            res = mod._run_scripts(str(tmp_path))
    assert spy.call_count == 2
    # Ensure two subprocess calls were attempted
    assert run_mock.call_count == 2
    assert res["install_rc"] == 0 and res["play_rc"] == 127

def test_lambda_handler_happy_path_puts_result(tmp_path, reload_handler_with_s3, monkeypatch):
    pages = [
        {"Contents": [{"Key": "jobs/123/run.sh"}]},
    ]
    fake_s3, calls = _fake_s3(pages=pages)
    mod = reload_handler_with_s3(fake_s3)

    # Stub helpers to avoid real downloads/exec
    monkeypatch.setattr(mod, "_download_prefix", lambda prefix, wd: None)
    monkeypatch.setattr(mod, "_run_scripts", lambda wd: {"install_rc": 0, "play_rc": 0, "play_out": "ok"})

    # Make temporary dirs deterministic
    wd = tmp_path / "work"
    wd.mkdir(parents=True)
    monkeypatch.setattr(tempfile, "mkdtemp", lambda: str(wd))

    event = {
        "Records": [
            {"body": json.dumps({"s3_prefix": "jobs/123/"})}
        ]
    }
    out = mod.lambda_handler(event, context={})
    assert out == {"ok": True}

    # Ensure result was uploaded to expected key
    assert calls["put"], "Expected put_object to be called"
    key, body = calls["put"][0]
    assert key == "jobs/123/result.json"
    result_obj = json.loads(body.decode("utf-8"))
    assert result_obj["install_rc"] == 0
    assert result_obj["play_rc"] == 0
    assert result_obj["play_out"] == "ok"

def test_lambda_handler_skips_records_without_prefix(reload_handler_with_s3):
    fake_s3, calls = _fake_s3(pages=[])
    mod = reload_handler_with_s3(fake_s3)

    # Spy to ensure helpers are not called
    with mock.patch.object(mod, "_download_prefix") as dl, mock.patch.object(mod, "_run_scripts") as run:
        out = mod.lambda_handler({"Records": [{"body": "{}"}, {"body": {"foo": "bar"}}]}, context={})
    assert out == {"ok": True}
    dl.assert_not_called()
    run.assert_not_called()
    assert calls["put"] == []

def test_lambda_handler_accepts_dict_body_and_string_body(reload_handler_with_s3, monkeypatch):
    fake_s3, calls = _fake_s3(pages=[])
    mod = reload_handler_with_s3(fake_s3)

    monkeypatch.setattr(mod, "_download_prefix", lambda prefix, wd: None)
    monkeypatch.setattr(mod, "_run_scripts", lambda wd: {})

    event = {
        "Records": [
            {"body": {"s3_prefix": "A/"}},
            {"body": json.dumps({"s3_prefix": "B/"})},
        ]
    }
    mod.lambda_handler(event, context={})
    # Both prefixes should upload results
    keys = [k for (k, _) in calls["put"]]
    assert keys == ["A/result.json", "B/result.json"]

def test_lambda_handler_cleans_up_temp_dir(tmp_path, reload_handler_with_s3, monkeypatch):
    fake_s3, calls = _fake_s3(pages=[])
    mod = reload_handler_with_s3(fake_s3)

    monkeypatch.setattr(mod, "_download_prefix", lambda prefix, wd: None)
    monkeypatch.setattr(mod, "_run_scripts", lambda wd: {})

    wd = tmp_path / "to_be_removed"
    wd.mkdir()
    monkeypatch.setattr(tempfile, "mkdtemp", lambda: str(wd))

    # Spy on shutil.rmtree to ensure cleanup happens
    with mock.patch("shutil.rmtree") as rm:
        mod.lambda_handler({"Records": [{"body": {"s3_prefix": "x/"}}]}, context={})
    rm.assert_called_once()
    # Even if rmtree ignores errors, ensure the call targeted our wd
    args, kwargs = rm.call_args
    assert args[0] == str(wd)
    assert kwargs.get("ignore_errors", False) is True

def test_lambda_handler_handles_run_scripts_failure_and_still_uploads_result(reload_handler_with_s3, monkeypatch):
    fake_s3, calls = _fake_s3(pages=[])
    mod = reload_handler_with_s3(fake_s3)

    monkeypatch.setattr(mod, "_download_prefix", lambda prefix, wd: None)
    # Simulate a failing playbook
    monkeypatch.setattr(mod, "_run_scripts", lambda wd: {"install_rc": 0, "play_rc": 2, "play_err": "boom"})

    mod.lambda_handler({"Records": [{"body": {"s3_prefix": "fail/"}}]}, context={})
    assert calls["put"], "Result should be uploaded even on failure"
    key, body = calls["put"][0]
    assert key == "fail/result.json"
    payload = json.loads(body.decode("utf-8"))
    assert payload["play_rc"] == 2
    assert payload["play_err"] == "boom"