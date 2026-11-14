import hashlib
import queue
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.hashing import HashWorker


def test_hash_matches_manual_sha256(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"hello systema" * 1000)
    expected = hashlib.sha256(f.read_bytes()).hexdigest()

    results: "queue.Queue" = queue.Queue()
    w = HashWorker(lambda pid, path, digest: results.put((pid, path, digest)))
    w.start()
    try:
        w.request(111, str(f))
        pid, path, digest = results.get(timeout=5)
        assert pid == 111
        assert digest == expected
    finally:
        w.stop()


def test_missing_file_returns_none(tmp_path):
    results: "queue.Queue" = queue.Queue()
    w = HashWorker(lambda pid, path, digest: results.put((pid, path, digest)))
    w.start()
    try:
        w.request(222, str(tmp_path / "does-not-exist.exe"))
        pid, path, digest = results.get(timeout=5)
        assert digest is None
    finally:
        w.stop()


def test_na_marker_short_circuits_without_touching_disk():
    results: "queue.Queue" = queue.Queue()
    w = HashWorker(lambda pid, path, digest: results.put((pid, path, digest)))
    w.start()
    try:
        w.request(333, "<n/a>")
        pid, path, digest = results.get(timeout=2)
        assert digest is None
    finally:
        w.stop()


def test_worker_survives_callback_exception(tmp_path):
    """Если on_result сам бросит исключение (баг в вызывающем коде), фоновый
    поток хэширования не должен навсегда умереть — следующий запрос должен
    всё ещё обработаться. Раньше исключение из callback'а на пути попадания
    в кэш перехватывалось общим except и приводило к повторному, уже неверному
    вызову callback'а; если бы и он упал — поток умирал молча."""
    f = tmp_path / "c.bin"
    f.write_bytes(b"resilience")
    expected = hashlib.sha256(f.read_bytes()).hexdigest()

    calls = {"n": 0}
    results: "queue.Queue" = queue.Queue()

    def flaky_on_result(pid, path, digest):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("симулированный баг в обработчике результата")
        results.put((pid, path, digest))

    w = HashWorker(flaky_on_result)
    w.start()
    try:
        w.request(1, str(f))      # этот callback бросит исключение
        w.request(2, str(f))      # поток должен быть всё ещё жив и обработать его
        pid, path, digest = results.get(timeout=5)
        assert pid == 2
        assert digest == expected
    finally:
        w.stop()


def test_request_survives_callback_exception_on_cache_hit(tmp_path):
    """request() на попадании в кэш вызывает callback СИНХРОННО, в потоке
    вызывающего (например, потока опроса в core/monitor.py). Если callback
    упадёт здесь, это не должно всплыть в вызывающий код — иначе один
    сбойный обработчик результата мог бы сорвать целый тик опроса."""
    f = tmp_path / "d.bin"
    f.write_bytes(b"sync-path")

    def always_raises(pid, path, digest):
        raise RuntimeError("симулированный баг")

    w = HashWorker(always_raises)
    w.start()
    try:
        w.request(1, str(f))
        time.sleep(0.3)   # дать воркеру посчитать и закэшировать
        # второй запрос того же файла идёт по синхронному cache-hit пути
        # прямо в request() — не должен поднять исключение наружу
        w.request(2, str(f))
    finally:
        w.stop()


def test_cache_avoids_rehash_of_unchanged_file(tmp_path, monkeypatch):
    f = tmp_path / "b.bin"
    f.write_bytes(b"cache me")

    calls = {"n": 0}
    import core.hashing as hashing_mod
    real_hash_one = hashing_mod.HashWorker._hash_one

    def counting_hash_one(self, pid, path):
        calls["n"] += 1
        return real_hash_one(self, pid, path)

    monkeypatch.setattr(hashing_mod.HashWorker, "_hash_one", counting_hash_one)

    results: "queue.Queue" = queue.Queue()
    w = hashing_mod.HashWorker(lambda pid, path, digest: results.put(digest))
    w.start()
    try:
        w.request(1, str(f))
        d1 = results.get(timeout=5)
        # второй запрос того же файла должен попасть в кэш до постановки в очередь
        w.request(2, str(f))
        d2 = results.get(timeout=5)
        assert d1 == d2
        assert calls["n"] == 1
    finally:
        w.stop()
