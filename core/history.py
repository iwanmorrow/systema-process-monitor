"""SYSTEMA Processes — история START/EXIT.

В памяти держим только последние N событий (для отклика GUI), но полная
история безопасно льётся на диск в SQLite через отдельный поток-писатель —
polling и GUI никогда не ждут дисковый I/O. Формат на диске рассчитан на
расследование постфактум: файл можно открыть любым SQLite-клиентом или
скриптом уже после того, как процесс, который всё это устроил, исчез.
"""

from __future__ import annotations

import json
import queue
import sqlite3
import threading
from collections import deque
from typing import Deque, List, Optional

from .models import HistoryEvent, Severity

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    ts REAL, kind TEXT, source TEXT, pid INTEGER, ppid INTEGER,
    create_time REAL, name TEXT, exe TEXT, cmdline TEXT, username TEXT,
    parent_chain TEXT, sha256 TEXT, severity TEXT, reasons TEXT, exit_code INTEGER
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_pid ON events(pid);
"""

_FLUSH_BATCH = 50        # сбрасывать на диск, когда накопилось столько строк
_FLUSH_MAX = 2000        # потолок одной транзакции при всплеске событий
_CLOSE_TIMEOUT = 30.0    # сколько close() ждёт досброса очереди на диск


class HistoryStore:
    """deque в памяти (для GUI) + асинхронная запись в SQLite (для расследований).

    db_path=None отключает диск (например, для юнит-тестов) — deque работает
    как и раньше в старой версии.
    """

    def __init__(self, mem_limit: int = 20000, db_path: Optional[str] = None):
        self.mem: Deque[HistoryEvent] = deque(maxlen=mem_limit)
        self._db_path = db_path
        self._queue: "queue.Queue" = queue.Queue()
        self._thread: Optional[threading.Thread] = None
        self._write_error: Optional[str] = None
        if db_path:
            self._thread = threading.Thread(target=self._writer, daemon=True)
            self._thread.start()

    def add(self, event: HistoryEvent) -> None:
        self.mem.append(event)
        if self._thread:
            self._queue.put(event)

    def close(self) -> bool:
        """Дождаться записи всего, что уже принято add(). True — всё на диске.

        Ожидание намеренно длинное (_CLOSE_TIMEOUT): прежний таймаут в 2 с
        молча терял хвост очереди при всплеске событий. Если за отведённое
        время писатель не справился (диск завис), это не скрывается —
        возвращается False и выставляется write_error."""
        if not self._thread:
            return True
        self._queue.put(None)
        self._thread.join(timeout=_CLOSE_TIMEOUT)
        if self._thread.is_alive():
            self._write_error = "close-timeout"
            return False
        return True

    def __len__(self) -> int:
        return len(self.mem)

    @property
    def write_error(self) -> Optional[str]:
        return self._write_error

    def _writer(self) -> None:
        try:
            conn = sqlite3.connect(self._db_path, check_same_thread=False)
            conn.executescript(_SCHEMA)
            conn.commit()
        except sqlite3.Error as exc:
            self._write_error = str(exc)
            return

        batch: List[HistoryEvent] = []
        while True:
            try:
                item = self._queue.get(timeout=1.0)
                timed_out = False
            except queue.Empty:
                item = None
                timed_out = True

            stop = item is None and not timed_out        # сентинел от close()
            if item is not None:
                batch.append(item)
                # забрать всё, что уже накопилось, одной транзакцией — при
                # всплеске это на порядки дешевле, чем commit на каждые 50 строк
                while len(batch) < _FLUSH_MAX:
                    try:
                        nxt = self._queue.get_nowait()
                    except queue.Empty:
                        break
                    if nxt is None:
                        stop = True
                        break
                    batch.append(nxt)

            if batch and (stop or timed_out or len(batch) >= _FLUSH_BATCH):
                self._flush(conn, batch)
                batch = []
            if stop:
                conn.close()
                return

    def _flush(self, conn: sqlite3.Connection, batch: List[HistoryEvent]) -> None:
        if not batch:
            return
        try:
            conn.executemany(
                "INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [(e.ts, e.kind, e.source, e.pid, e.ppid, e.create_time, e.name,
                  e.exe, e.cmdline, e.username, e.parent_chain, e.sha256,
                  e.severity.value if isinstance(e.severity, Severity) else str(e.severity),
                  json.dumps(e.reasons), e.exit_code)
                 for e in batch])
            conn.commit()
        except sqlite3.Error as exc:
            self._write_error = str(exc)
        batch.clear()
