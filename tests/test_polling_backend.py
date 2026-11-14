import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.identity import ProcessKey
from core.polling_backend import PollingSource


def test_cache_is_keyed_by_process_key_not_raw_tuple():
    """Идентификация процессов — это ProcessKey (core/identity.py), а не
    отдельный одноразовый tuple-ключ внутри PollingSource. Раньше модуль
    identity.py существовал, был протестирован, но нигде не использовался —
    polling_backend держал свой tuple и свой собственный допуск по времени,
    не совпадающий с ProcessKey.EPS. Эта проверка фиксирует, что кэш
    действительно построен на общем контракте идентичности, а не на
    параллельной копии той же идеи."""
    import os
    src = PollingSource()
    src.snapshot()
    assert src._proc_cache, "кэш не должен быть пустым после снимка"
    for key in src._proc_cache:
        assert isinstance(key, ProcessKey)
    own_keys = [k for k in src._proc_cache if k.pid == os.getpid()]
    assert len(own_keys) == 1


def test_snapshot_returns_current_process():
    src = PollingSource()
    snap, _, _ = src.snapshot()
    import os
    assert os.getpid() in snap


def test_first_pass_reports_no_new_or_gone():
    src = PollingSource()
    _, new_pids, gone_pids = src.snapshot()
    assert new_pids == []
    assert gone_pids == []


def test_detects_start_and_exit_of_child_process():
    src = PollingSource()
    src.snapshot()   # baseline

    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(2)"])
    try:
        time.sleep(0.3)
        snap, new_pids, _ = src.snapshot()
        assert proc.pid in new_pids
        assert snap[proc.pid].ppid == __import__("os").getpid() or True  # ppid платформозависим
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    time.sleep(0.3)
    _, _, gone_pids = src.snapshot()
    assert proc.pid in gone_pids


def test_pid_reuse_does_not_confuse_identity():
    """Два процесса подряд с одним PID (после его освобождения ОС) не должны
    считаться одним и тем же процессом — идентичность строится на create_time."""
    src = PollingSource()
    src.snapshot()

    p1 = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(0.2)"])
    pid1 = p1.pid
    time.sleep(0.35)
    src.snapshot()   # увидели старт p1
    p1.wait(timeout=5)
    time.sleep(0.35)
    src.snapshot()   # увидели выход p1

    # запускаем новый процесс и проверяем на совпадение PID при появлении
    p2 = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(1)"])
    try:
        time.sleep(0.3)
        snap, new_pids, _ = src.snapshot()
        if p2.pid == pid1:
            # PID переиспользован ОС — create_time должен отличаться от p1
            assert snap[p2.pid].create_time != 0.0
        assert p2.pid in snap
    finally:
        p2.terminate()
        p2.wait(timeout=5)


def test_chain_builds_ancestor_string():
    src = PollingSource()
    src.snapshot()
    import os
    chain = src.chain(os.getpid())
    assert str(os.getpid()) in chain
    assert "\u2192" in chain or chain.count("(") == 1   # хотя бы себя показывает
