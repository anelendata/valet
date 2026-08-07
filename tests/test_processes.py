import sys
import threading
import time

from valet.broker import Broker


def _wait_for(predicate, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.01)
    raise AssertionError("timed out waiting for condition")


def test_can_list_and_kill_valet_subprocess(cfg):
    broker = Broker(cfg)
    events = []
    script = "import time; print('ready', flush=True); time.sleep(60)"

    def run_stream():
        events.extend(broker.handle_stream({
            "op": "exec",
            "cmd": [sys.executable, "-c", script],
            "shell": False,
            "timeout": 60,
        }))

    thread = threading.Thread(target=run_stream)
    thread.start()
    try:
        listed = _wait_for(lambda: broker.handle({"op": "processes.list"})["processes"])
        pid = listed[0]["pid"]

        kill_resp = broker.handle({"op": "processes.kill", "pid": pid})

        assert kill_resp == {
            "broker_version": kill_resp["broker_version"],
            "op": "processes.kill",
            "ok": True,
            "pid": pid,
            "killed": True,
        }
        thread.join(timeout=2)
        assert not thread.is_alive()
        _wait_for(lambda: broker.handle({"op": "processes.list"})["processes"] == [])
    finally:
        if thread.is_alive():
            for item in broker.handle({"op": "processes.list"})["processes"]:
                broker.handle({"op": "processes.kill", "pid": item["pid"]})
            thread.join(timeout=2)


def test_kill_untracked_pid_is_denied(cfg):
    resp = Broker(cfg).handle({"op": "processes.kill", "pid": 999999})

    assert resp["ok"] is False
    assert resp["error_class"] == "PolicyDenied"
    assert resp["detail"] == "process is not a valet subprocess"
