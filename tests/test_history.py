import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.history import HistoryStore
from core.models import HistoryEvent, Severity


def make_event(pid=1, kind="START", ts=None):
    return HistoryEvent(
        ts=ts or time.time(), kind=kind, source="poll", pid=pid, ppid=1,
        create_time=100.0, name="test.exe", exe="/bin/test", cmdline="test.exe",
        username="root", parent_chain="init(1) \u2192 test.exe(1)",
        sha256=None, severity=Severity.NONE, reasons=[])


def test_memory_is_bounded():
    store = HistoryStore(mem_limit=5, db_path=None)
    for i in range(20):
        store.add(make_event(pid=i))
    assert len(store) == 5
    assert store.mem[-1].pid == 19   # последние 5 остаются, самые новые


def test_no_db_path_disables_disk_write():
    store = HistoryStore(mem_limit=10, db_path=None)
    store.add(make_event())
    store.close()   # не должно падать без писателя


def test_sqlite_writer_persists_events(tmp_path):
    db = tmp_path / "history.sqlite3"
    store = HistoryStore(mem_limit=100, db_path=str(db))
    for i in range(3):
        store.add(make_event(pid=1000 + i))
    store.close()   # ждёт финального flush

    conn = sqlite3.connect(str(db))
    rows = conn.execute("SELECT pid, kind, severity FROM events ORDER BY pid").fetchall()
    conn.close()
    assert [r[0] for r in rows] == [1000, 1001, 1002]
    assert all(r[1] == "START" for r in rows)
    assert all(r[2] == "NONE" for r in rows)


def test_sqlite_reasons_are_stable_codes_not_localized_text(tmp_path):
    """Персистентный формат reasons — (code, params), НЕ готовый текст на
    каком-то языке: core не выбирает язык, это забота GUI/i18n при отображении
    (см. presentation.render_reason). Если бы сюда попал уже переведённый текст, он
    навсегда застыл бы на языке момента записи — именно такой баг и просили
    исключить архитектурно, а не точечными правками."""
    db = tmp_path / "history2.sqlite3"
    store = HistoryStore(mem_limit=10, db_path=str(db))
    ev = make_event(pid=42)
    ev.reasons = [("temp-path", {"exe": "/tmp/evil.exe"}),
                 ("suspicious-cmdline", {"tokens": "-enc"})]
    ev.severity = Severity.HIGH
    store.add(ev)
    store.close()

    import json
    conn = sqlite3.connect(str(db))
    row = conn.execute("SELECT reasons, severity FROM events WHERE pid=42").fetchone()
    conn.close()
    stored = json.loads(row[0])
    assert stored == [["temp-path", {"exe": "/tmp/evil.exe"}],
                      ["suspicious-cmdline", {"tokens": "-enc"}]]
    # ни один код правила не должен сам быть предложением на естественном
    # языке — это были бы ровно те "localized display strings", которых быть
    # не должно в хранимых данных
    for code, _params in stored:
        assert " " not in code
    assert row[1] == "HIGH"


def test_close_flushes_every_event_across_multiple_batches(tmp_path):
    """137 событий подряд (больше двух внутренних батчей по 50) и немедленный
    close(): в SQLite должны оказаться все до единого — штатное завершение не
    имеет права терять уже принятые историей события."""
    db = tmp_path / "many.sqlite3"
    store = HistoryStore(mem_limit=10, db_path=str(db))
    for i in range(137):
        store.add(make_event(pid=i))
    store.close()

    conn = sqlite3.connect(str(db))
    count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    pids = {r[0] for r in conn.execute("SELECT pid FROM events")}
    conn.close()
    assert count == 137
    assert pids == set(range(137))


def test_burst_of_events_is_fully_persisted_on_close(tmp_path):
    """Всплеск событий (много больше размера батча) + немедленный close():
    раньше close() ждал писателя не дольше 2 с и молча терял хвост очереди
    (на 100 000 событий — 18 450 строк). Теперь close() ждёт полного досброса
    и сообщает результат."""
    db = tmp_path / "burst.sqlite3"
    store = HistoryStore(mem_limit=100, db_path=str(db))
    n = 30_000
    for i in range(n):
        store.add(make_event(pid=i))
    assert store.close() is True
    assert len(store) == 100      # память остаётся ограниченной
    conn = sqlite3.connect(str(db))
    count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    conn.close()
    assert count == n


def test_history_persists_across_restart_but_memory_starts_empty(tmp_path):
    """Задуманное и теперь явно проверяемое поведение: SQLite — журнал для
    расследований, он дописывается между запусками; вкладка «История событий»
    после перезапуска начинается с пустой памяти (прошлые сессии в GUI не
    подгружаются — см. README, раздел «История и персистентность»)."""
    db = tmp_path / "restart.sqlite3"
    first = HistoryStore(mem_limit=10, db_path=str(db))
    first.add(make_event(pid=1))
    first.close()

    second = HistoryStore(mem_limit=10, db_path=str(db))
    assert len(second) == 0
    second.add(make_event(pid=2))
    second.close()

    conn = sqlite3.connect(str(db))
    pids = sorted(r[0] for r in conn.execute("SELECT pid FROM events"))
    conn.close()
    assert pids == [1, 2]
