import queue
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.models import SignatureInfo
from core.signature_worker import SignatureWorker


def test_checker_result_is_delivered(tmp_path):
    f = tmp_path / "a.exe"
    f.write_bytes(b"binary")

    def checker(path):
        return SignatureInfo(status="signed", signer="Acme Ltd", checked=True)

    results: "queue.Queue" = queue.Queue()
    w = SignatureWorker(checker, lambda pid, path, sig: results.put((pid, path, sig)))
    w.start()
    try:
        w.request(1, str(f))
        pid, path, sig = results.get(timeout=5)
        assert pid == 1
        assert sig.status == "signed"
        assert sig.signer == "Acme Ltd"
    finally:
        w.stop()


def test_checker_is_not_called_twice_for_unchanged_file(tmp_path):
    f = tmp_path / "b.exe"
    f.write_bytes(b"binary")

    calls = {"n": 0}

    def checker(path):
        calls["n"] += 1
        return SignatureInfo(status="unsigned", checked=True)

    results: "queue.Queue" = queue.Queue()
    w = SignatureWorker(checker, lambda pid, path, sig: results.put(sig))
    w.start()
    try:
        w.request(1, str(f))
        results.get(timeout=5)
        w.request(2, str(f))
        results.get(timeout=5)
        assert calls["n"] == 1
    finally:
        w.stop()


def test_missing_file_yields_default_signature_info(tmp_path):
    results: "queue.Queue" = queue.Queue()
    w = SignatureWorker(lambda p: SignatureInfo(status="signed", checked=True),
                        lambda pid, path, sig: results.put(sig))
    w.start()
    try:
        w.request(1, str(tmp_path / "missing.exe"))
        sig = results.get(timeout=5)
        assert sig.checked is False
        assert sig.status == "unknown"
    finally:
        w.stop()


def test_na_marker_short_circuits_without_calling_checker():
    calls = {"n": 0}

    def checker(path):
        calls["n"] += 1
        return SignatureInfo(status="signed", checked=True)

    results: "queue.Queue" = queue.Queue()
    w = SignatureWorker(checker, lambda pid, path, sig: results.put(sig))
    w.start()
    try:
        w.request(1, "<n/a>")
        sig = results.get(timeout=2)
        assert sig.checked is False
        assert calls["n"] == 0
    finally:
        w.stop()


def test_checker_exception_does_not_corrupt_cache_or_crash_worker(tmp_path):
    """Раньше исключение внутри checker()'а ловилось общим except, который
    сам же писал в кэш по неверному ключу (path, 0.0) и мог затереть ранее
    корректно посчитанный результат при столкновении ключей. Эта проверка
    фиксирует, что сбойная проверка не ломает последующие успешные."""
    f = tmp_path / "c.exe"
    f.write_bytes(b"binary")

    calls = {"n": 0}

    def flaky_checker(path):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("симулированный сбой проверки подписи")
        return SignatureInfo(status="signed", signer="Acme", checked=True)

    results: "queue.Queue" = queue.Queue()
    w = SignatureWorker(flaky_checker, lambda pid, path, sig: results.put(sig))
    w.start()
    try:
        w.request(1, str(f))
        first = results.get(timeout=5)
        assert first.checked is False   # сбой -> дефолтный SignatureInfo

        # второй запрос ТОГО ЖЕ файла не должен попасть в "кэш сбоя" навечно —
        # файл не менялся, но мы используем отдельный ключ для сбоев, так что
        # повторная проверка действительно происходит и может быть успешной
        w.request(2, str(f))
        second = results.get(timeout=5)
        assert second.checked is True
        assert second.status == "signed"
    finally:
        w.stop()


def test_worker_survives_callback_exception(tmp_path):
    f = tmp_path / "d.exe"
    f.write_bytes(b"binary")

    calls = {"n": 0}
    results: "queue.Queue" = queue.Queue()

    def flaky_on_result(pid, path, sig):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("симулированный баг в обработчике результата")
        results.put((pid, sig))

    w = SignatureWorker(lambda p: SignatureInfo(status="signed", checked=True),
                        flaky_on_result)
    w.start()
    try:
        w.request(1, str(f))       # этот callback бросит исключение
        time.sleep(0.3)
        w.request(2, str(f))       # поток должен быть всё ещё жив
        pid, sig = results.get(timeout=5)
        assert pid == 2
        assert sig.status == "signed"
    finally:
        w.stop()
