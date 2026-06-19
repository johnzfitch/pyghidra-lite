"""Tests for _run_bounded (the open-timeout watchdog) and _env_float.

Both are pure-Python (no JVM), so they run under pytest without the JPype segfault.
_run_bounded is the core of the wedge-prevention fix: it must return values, propagate
exceptions, and -- critically -- time out quickly instead of hanging.
"""
import time

import pytest

from pyghidra_lite import server


class TestRunBounded:
    def test_returns_value(self):
        assert server._run_bounded(lambda: 42, 5, "ok") == 42

    def test_returns_none_legitimately(self):
        # A real None return must be distinguishable from a timeout (which raises).
        assert server._run_bounded(lambda: None, 5, "none") is None

    def test_propagates_exception(self):
        def boom():
            raise ValueError("boom")

        with pytest.raises(ValueError, match="boom"):
            server._run_bounded(boom, 5, "err")

    def test_times_out_quickly_without_hanging(self):
        t0 = time.monotonic()
        with pytest.raises(TimeoutError, match="wedged"):
            server._run_bounded(lambda: time.sleep(30), 0.3, "slow")
        elapsed = time.monotonic() - t0
        # Bounded by the timeout, nowhere near the 30s the call would have taken.
        assert elapsed < 3, f"took {elapsed}s -- watchdog did not bound the call"

    def test_op_desc_in_timeout_message(self):
        with pytest.raises(TimeoutError, match="myop"):
            server._run_bounded(lambda: time.sleep(5), 0.2, "myop")

    def test_caller_thread_not_blocked_past_timeout(self):
        # The bounded call must hand control back to the caller at the timeout even
        # though the worker thread is still running (it's abandoned as a daemon).
        t0 = time.monotonic()
        with pytest.raises(TimeoutError):
            server._run_bounded(lambda: time.sleep(10), 0.2, "x")
        assert time.monotonic() - t0 < 2


class TestEnvFloat:
    def test_missing_returns_default(self, monkeypatch):
        monkeypatch.delenv("PYGHIDRA_LITE_TEST_F", raising=False)
        assert server._env_float("PYGHIDRA_LITE_TEST_F", 7.5) == 7.5

    def test_valid_parsed(self, monkeypatch):
        monkeypatch.setenv("PYGHIDRA_LITE_TEST_F", "123")
        assert server._env_float("PYGHIDRA_LITE_TEST_F", 7.5) == 123.0

    def test_invalid_falls_back_to_default(self, monkeypatch):
        # A malformed override must not raise (which would break module import).
        monkeypatch.setenv("PYGHIDRA_LITE_TEST_F", "not-a-number")
        assert server._env_float("PYGHIDRA_LITE_TEST_F", 7.5) == 7.5

    def test_empty_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("PYGHIDRA_LITE_TEST_F", "")
        assert server._env_float("PYGHIDRA_LITE_TEST_F", 7.5) == 7.5
