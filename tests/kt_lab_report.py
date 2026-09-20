"""Reporting-only pytest events, adapted from the preserved proof-kit reporter.

No item, selection, skip or outcome mutation. Output must be new and external.
"""
import json
import os
from pathlib import Path
import time

import pytest

_PATH = None


def _append(event):
    if _PATH is None:
        return
    event["monotonic_ns"] = time.monotonic_ns()
    with _PATH.open("a", encoding="utf8", newline="\n") as stream:
        stream.write(json.dumps(event, sort_keys=True, allow_nan=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def pytest_configure(config):
    global _PATH
    _PATH = Path(os.environ["KT_REPORT_PATH"])
    if not _PATH.is_absolute() or _PATH.exists():
        raise RuntimeError("report path must be new and absolute")
    repo = Path(__file__).resolve().parents[1]
    if _PATH.resolve().is_relative_to(repo):
        raise RuntimeError("report must be external to source")
    _PATH.parent.mkdir(parents=True, exist_ok=True)
    _PATH.touch(exist_ok=False)
    _append({"event": "configured", "collect_only": bool(config.option.collectonly)})


def pytest_collection_finish(session):
    _append({"event": "collection", "nodeids": [item.nodeid for item in session.items]})


def pytest_runtest_logreport(report):
    _append({"event": "test", "nodeid": report.nodeid, "phase": report.when,
             "outcome": report.outcome, "xfail": hasattr(report, "wasxfail"), "duration": report.duration})


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    result = yield
    report = result.get_result()
    if report.failed and call.excinfo is not None:
        for entry in call.excinfo.traceback:
            value = entry.frame.f_locals.get("result")
            if type(value) is dict and value.get("status") == "FAIL":
                _append({"event": "runtime_failure_context", "nodeid": item.nodeid,
                         "result": {key: value[key] for key in ("status", "where", "error") if key in value}})


def pytest_sessionfinish(session, exitstatus):
    _append({"event": "finish", "exitstatus": int(exitstatus), "collected": session.testscollected})
