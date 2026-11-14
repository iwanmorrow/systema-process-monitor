"""SYSTEMA Processes — SHA-256 исполняемых файлов в фоне.

Хэш нужен один раз на файл, не на процесс: десять процессов одного chrome.exe
дают один хэш. Кэш ключится по (путь, размер, mtime) — правка файла не
подсовывает старый хэш, а повторный запуск того же бинарника не пересчитывает
его заново. Всё считается в отдельном потоке через очередь — ни GUI, ни поток
опроса не ждут дискового I/O.
"""

from __future__ import annotations

import hashlib
import os
import queue
import threading
from typing import Callable, Dict, Optional, Tuple

CacheKey = Tuple[str, int, float]   # путь, размер, mtime

_CHUNK = 1024 * 1024


class HashWorker:
    """Один фоновый поток, очередь путей, callback(pid, path, sha256|None)."""

    def __init__(self, on_result: Callable[[int, str, Optional[str]], None]):
        self._on_result = on_result
        self._queue: "queue.Queue[Tuple[int, str]]" = queue.Queue()
        self._cache: Dict[CacheKey, Optional[str]] = {}
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._stop = threading.Event()

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._queue.put((-1, ""))   # разбудить поток, чтобы он увидел флаг

    def _deliver(self, pid: int, path: str, value: Optional[str]) -> None:
        """Единственное место, где реально вызывается внешний callback.
        Вызывающий код (request() — синхронно из потока producer'а, или
        _hash_one — асинхронно из фонового потока) не должен зависеть от
        того, что callback написан без ошибок: падение здесь перехватывается
        и не распространяется ни на producer, ни на фоновый поток."""
        try:
            self._on_result(pid, path, value)
        except Exception:  # noqa: BLE001
            pass

    def request(self, pid: int, path: str) -> None:
        """Поставить файл в очередь на хэширование. Никогда не блокирует."""
        if not path or path.startswith("<"):
            self._deliver(pid, path, None)
            return
        try:
            st = os.stat(path)
        except OSError:
            self._deliver(pid, path, None)
            return
        key = (path, st.st_size, st.st_mtime)
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
                self._hash_one(pid, path)
            except Exception:  # noqa: BLE001
                # _hash_one сам не должен сюда долетать (см. ниже), но это —
                # последний рубеж: даже баг в коде обработчика результата не
                # должен навсегда убить фоновый поток хэширования.
                pass

    def _hash_one(self, pid: int, path: str) -> None:
        """Вычисление результата и его доставка через callback разделены
        намеренно: если _on_result сам бросит исключение, это не должно
        попасть в except ниже и превратиться в повторный, уже неверный вызов
        callback'а (например, после успешного попадания в кэш)."""
        result: Optional[str]
        try:
            st = os.stat(path)
            key = (path, st.st_size, st.st_mtime)
            with self._lock:
                cached = self._cache.get(key)
            if cached is not None:
                result = cached
            else:
                digest = hashlib.sha256()
                with open(path, "rb") as fh:
                    while True:
                        chunk = fh.read(_CHUNK)
                        if not chunk:
                            break
                        digest.update(chunk)
                result = digest.hexdigest()
                with self._lock:
                    self._cache[key] = result
        except (OSError, PermissionError):
            result = None
        except Exception:  # noqa: BLE001
            result = None
        self._deliver(pid, path, result)
