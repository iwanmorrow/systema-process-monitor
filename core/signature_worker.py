"""SYSTEMA Processes — фоновая проверка цифровой подписи.

Сама проверка инжектируется извне (`checker`): на Windows это
`windows.signature.check` (Authenticode через WinVerifyTrust), на остальных
платформах вызывающий код просто не создаёт этот воркер — Authenticode
специфичен для Windows, а честной кроссплатформенной замены (codesign на
macOS, ничего сравнимого на большинстве Linux) пока нет, и притворяться, что
она есть, хуже, чем не показывать поле вовсе.
"""

from __future__ import annotations

import os
import queue
import threading
from typing import Callable, Dict, Tuple

from .models import SignatureInfo

CacheKey = Tuple[str, float]   # путь, mtime


class SignatureWorker:
    def __init__(self, checker: Callable[[str], SignatureInfo],
                 on_result: Callable[[int, str, SignatureInfo], None]):
        self._checker = checker
        self._on_result = on_result
        self._queue: "queue.Queue[Tuple[int, str]]" = queue.Queue()
        self._cache: Dict[CacheKey, SignatureInfo] = {}
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._stop = threading.Event()

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._queue.put((-1, ""))

    def _deliver(self, pid: int, path: str, value: SignatureInfo) -> None:
        """Единственное место, где реально вызывается внешний callback — см.
        подробный комментарий к одноимённому методу в core.hashing.HashWorker."""
        try:
            self._on_result(pid, path, value)
        except Exception:  # noqa: BLE001
            pass

    def request(self, pid: int, path: str) -> None:
        if not path or path.startswith("<"):
            self._deliver(pid, path, SignatureInfo())
            return
        try:
            mtime = os.stat(path).st_mtime
        except OSError:
            self._deliver(pid, path, SignatureInfo())
            return
        key = (path, mtime)
        with self._lock:
            cached = self._cache.get(key)
        if cached is not None:
            self._deliver(pid, path, cached)
            return
        self._queue.put((pid, path))

    def _run(self) -> None:
        while not self._stop.is_set():
            pid, path = self._queue.get()
            if pid == -1:
                break
            try:
                self._check_one(pid, path)
            except Exception:  # noqa: BLE001
                # Последний рубеж — см. аналогичный комментарий в hashing.py:
                # даже баг в обработчике результата не должен навсегда убить
                # фоновый поток проверки подписи.
                pass

    def _check_one(self, pid: int, path: str) -> None:
        """Вычисление результата и его доставка через callback разделены
        намеренно (см. core.hashing.HashWorker._hash_one — тот же мотив):
        если _on_result сам бросит исключение на пути попадания в кэш, это
        не должно быть ошибочно принято за сбой проверки подписи и не должно
        затирать уже корректно закэшированный результат."""
        key: Tuple[str, float]
        try:
            mtime = os.stat(path).st_mtime
            key = (path, mtime)
            with self._lock:
                cached = self._cache.get(key)
            if cached is not None:
                result = cached
            else:
                result = self._checker(path)
        except Exception:  # noqa: BLE001
            result = SignatureInfo()
            key = (path, -1.0)   # стабильный ключ для "файл недоступен/сбой проверки"

        with self._lock:
            self._cache[key] = result
        self._deliver(pid, path, result)
