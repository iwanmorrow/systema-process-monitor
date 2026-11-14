import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.backend import EventBackend
from core.models import SignatureInfo
from core.monitor import ProcessMonitor


class FakeEventBackend(EventBackend):
    """Синтезирует START для процесса ДО того, как polling успеет его увидеть —
    имитирует то, чем в реальности является WMI process trace."""

    available = True

    def __init__(self):
        self.error = ""
        self._on_event = None

    def start(self, on_event) -> bool:
        self._on_event = on_event
        return True

    def stop(self) -> None:
        pass

    def fire(self, kind, pid, ppid, name, exit_code=0):
        self._on_event(kind, pid, ppid, name, exit_code)


def test_monitor_without_event_backend_falls_back_to_polling(tmp_path):
    mon = ProcessMonitor(db_path=str(tmp_path / "h.sqlite3"))
    try:
        assert mon.event_backend_status == "disabled"
        snap, events = mon.poll()
        import os
        assert os.getpid() in snap
    finally:
        mon.shutdown()


def test_event_backend_start_is_not_duplicated_by_polling_fallback(tmp_path):
    backend = FakeEventBackend()
    mon = ProcessMonitor(db_path=str(tmp_path / "h.sqlite3"), event_backend=backend)
    try:
        assert mon.event_backend_status == "active"
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(2)"])
        try:
            # событийный бэкенд "узнаёт" о процессе первым
            backend.fire("START", proc.pid, 1, "python3")
            snap, events = mon.poll()
            starts = [e for e in events if e.kind == "START" and e.pid == proc.pid]
            assert len(starts) == 1
            assert starts[0].source == "wmi"

            # следующий тик увидит тот же процесс через polling — не должно
            # возникнуть второго START-события для того же pid
            time.sleep(0.2)
            snap2, events2 = mon.poll()
            dup_starts = [e for e in events2 if e.kind == "START" and e.pid == proc.pid]
            assert dup_starts == []
        finally:
            proc.terminate()
            proc.wait(timeout=5)
    finally:
        mon.shutdown()


def test_exit_event_from_backend_is_recorded():
    backend = FakeEventBackend()
    mon = ProcessMonitor(db_path=None, event_backend=backend)
    try:
        backend.fire("START", 99999, 1, "ghost.exe")
        _, events = mon.poll()
        assert any(e.kind == "START" and e.pid == 99999 for e in events)

        backend.fire("EXIT", 99999, 1, "ghost.exe", exit_code=1)
        _, events2 = mon.poll()
        exits = [e for e in events2 if e.kind == "EXIT" and e.pid == 99999]
        assert len(exits) == 1
        assert exits[0].exit_code == 1
    finally:
        mon.shutdown()


def test_signature_checker_feeds_heuristics(tmp_path):
    exe_path = tmp_path / "tool.exe"
    exe_path.write_bytes(b"fake binary")

    def fake_checker(path):
        return SignatureInfo(status="unsigned", signer="", checked=True)

    backend = FakeEventBackend()
    mon = ProcessMonitor(db_path=None, event_backend=backend,
                         signature_checker=fake_checker)
    try:
        # эмулируем появление процесса с известным путём через прямую вставку
        # в внутренний снимок способом, доступным публично: polling видит
        # только реально существующие процессы, поэтому проверяем воркер
        # напрямую через его публичный API дожидаясь результата в poll()
        mon._request_file_checks(12345, str(exe_path))
        deadline = time.time() + 5
        info = None
        while time.time() < deadline:
            mon.snapshot[12345] = mon.snapshot.get(
                12345) or __import__("core.models", fromlist=["ProcessInfo"]).ProcessInfo(
                pid=12345, exe=str(exe_path))
            mon._drain_sig_results(mon.snapshot)
            if mon.snapshot[12345].signature.checked:
                info = mon.snapshot[12345]
                break
            time.sleep(0.05)
        assert info is not None
        assert info.signature.status == "unsigned"
        assert any(h.code == "unsigned" for h in info.hits)
    finally:
        mon.shutdown()


def test_exit_of_process_running_before_startup_is_recorded():
    """Старый ProcessMonitor фиксировал EXIT любого процесса из прошлого
    снимка. Процессы, уже работавшие при запуске, обязаны попадать в
    «живые» после первого снимка, иначе их завершение теряется."""
    pre = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    time.sleep(0.3)
    mon = ProcessMonitor(db_path=None)
    try:
        mon.poll()
        pre.terminate()
        pre.wait(timeout=5)
        time.sleep(0.3)
        _, events = mon.poll()
        exits = [e for e in events if e.kind == "EXIT" and e.pid == pre.pid]
        assert len(exits) == 1
        # EXIT несёт то, что было известно из прошлого снимка, а не только имя
        assert exits[0].exe and exits[0].cmdline
    finally:
        mon.shutdown()
        if pre.poll() is None:
            pre.kill()


def _fake_snapshots(mon, snapshots):
    """Подменяет источник снимков заранее заданной последовательностью
    (snap, new_pids, gone_pids) — так PID reuse воспроизводится детерминированно."""
    it = iter(snapshots)

    class _Src:
        first_pass = False
        known = mon._poll.known

        def snapshot(self_inner):
            return next(it)

        def chain(self_inner, pid, depth=8):
            return f"p({pid})"

        def static_fields_for(self_inner, pid):
            return {"create_time": 0.0}

    mon._poll = _Src()


def test_pid_reuse_between_ticks_yields_exit_then_start():
    from core.models import ProcessInfo
    mon = ProcessMonitor(db_path=None)
    try:
        old = ProcessInfo(pid=777, ppid=1, name="old.exe", exe="/bin/old", create_time=1000.0)
        new = ProcessInfo(pid=777, ppid=1, name="new.exe", exe="/bin/new", create_time=9000.0)
        mon._active[777] = 1000.0
        mon.snapshot = {777: old}
        _fake_snapshots(mon, [({777: new}, [777], [])])
        _, events = mon.poll()
        kinds = [(e.kind, e.name) for e in events if e.pid == 777]
        assert kinds == [("EXIT", "old.exe"), ("START", "new.exe")]
        assert mon._active[777] == 9000.0
    finally:
        mon.shutdown()


def test_same_process_seen_by_both_sources_is_not_duplicated_even_with_time_jitter():
    from core.models import ProcessInfo
    mon = ProcessMonitor(db_path=None)
    try:
        proc = ProcessInfo(pid=555, ppid=1, name="a.exe", create_time=2000.01)
        mon._active[555] = 2000.0          # event-бэкенд записал с чуть другим create_time
        mon.snapshot = {}
        _fake_snapshots(mon, [({555: proc}, [555], [])])
        _, events = mon.poll()
        assert [e for e in events if e.pid == 555] == []
    finally:
        mon.shutdown()


def test_hash_is_marked_unavailable_when_image_path_is_unknown():
    """Нет пути к образу -> SHA-256 должен стать <n/a>, а не остаться None
    ("считается…") навсегда."""
    from core.models import NO_ACCESS, ProcessInfo
    mon = ProcessMonitor(db_path=None)
    try:
        no_exe = ProcessInfo(pid=31, ppid=1, name="mystery", exe=NO_ACCESS, create_time=1.0)
        empty_exe = ProcessInfo(pid=32, ppid=1, name="kthread", exe="", create_time=1.0)
        _fake_snapshots(mon, [({31: no_exe, 32: empty_exe}, [], [])])
        snap, _ = mon.poll()
        assert snap[31].sha256 == NO_ACCESS
        assert snap[32].sha256 == NO_ACCESS
    finally:
        mon.shutdown()
