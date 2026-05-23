from app.core import supabase_timeout


class SuccessfulFuture:
    def __init__(self, result_value):
        self.result_value = result_value
        self.timeout_used = None

    def result(self, timeout):
        self.timeout_used = timeout
        return self.result_value

    def cancel(self):
        raise AssertionError("cancel should not be called for successful futures")


class TimeoutFuture:
    def __init__(self):
        self.cancel_called = False

    def result(self, timeout):
        raise supabase_timeout.FuturesTimeoutError()

    def cancel(self):
        self.cancel_called = True


class FakeExecutor:
    def __init__(self, future):
        self.future = future
        self.submitted_operation = None

    def submit(self, operation):
        self.submitted_operation = operation
        return self.future


class FakeLogger:
    def __init__(self):
        self.messages = []

    def error(self, message):
        self.messages.append(message)


def test_run_supabase_with_timeout_returns_operation_result(monkeypatch):
    future = SuccessfulFuture(result_value={"status": "ok"})
    executor = FakeExecutor(future)

    monkeypatch.setattr(supabase_timeout, "_EXECUTOR", executor)

    result = supabase_timeout.run_supabase_with_timeout(
        lambda: {"status": "ignored"},
        timeout_s=5,
        operation_name="test_query",
    )

    assert result == {"status": "ok"}
    assert future.timeout_used == 5
    assert executor.submitted_operation is not None


def test_run_supabase_with_timeout_raises_custom_timeout(monkeypatch):
    future = TimeoutFuture()
    executor = FakeExecutor(future)
    fake_logger = FakeLogger()

    monkeypatch.setattr(supabase_timeout, "_EXECUTOR", executor)
    monkeypatch.setattr(supabase_timeout, "logger", fake_logger)

    try:
        supabase_timeout.run_supabase_with_timeout(
            lambda: None,
            timeout_s=1.5,
            operation_name="slow_query",
        )
    except supabase_timeout.SupabaseTimeoutError as exc:
        assert str(exc) == "slow_query timed out after 1.5s"
    else:
        raise AssertionError("SupabaseTimeoutError was not raised")

    assert future.cancel_called is True
    assert fake_logger.messages == ["slow_query timed out after 1.5s"]
