import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.identity import ProcessKey


def test_same_pid_same_time_is_same_process():
    a = ProcessKey(1234, 1000.000)
    b = ProcessKey(1234, 1000.010)   # разница в пределах округления источника
    assert a.same_process(b)


def test_reused_pid_is_different_process():
    a = ProcessKey(1234, 1000.0)
    b = ProcessKey(1234, 5000.0)     # тот же PID, но другой процесс во времени
    assert not a.same_process(b)


def test_different_pid_same_time_is_different_process():
    a = ProcessKey(1234, 1000.0)
    b = ProcessKey(5678, 1000.0)
    assert not a.same_process(b)


def test_key_is_hashable_and_usable_as_dict_key():
    a = ProcessKey(1, 100.0)
    b = ProcessKey(1, 100.0)
    d = {a: "x"}
    assert d[b] == "x"   # равные по значению ключи должны совпадать в dict
