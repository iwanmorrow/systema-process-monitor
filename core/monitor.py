"""SYSTEMA Processes — оркестратор.

Соединяет:
  - PollingSource   — снимки процессов + CPU/RAM/threads/handles. Всегда
                      активен и остаётся единственным источником изменяющихся
                      метрик — событийные механизмы ОС такую динамику не несут.
  - EventBackend    — event-driven START/EXIT (на Windows: WMI process trace,
                      см. windows/wmi_events.py). Если недоступен (нет прав
                      администратора, не Windows, WMI не подписался) —
                      используется diff от PollingSource: тот же код пути,
                      деградация только по задержке до одного тика, не по
                      составу данных.
  - HashWorker / SignatureWorker — SHA-256 и подпись образов в фоне, с кэшем.
  - RuleEngine      — эвристики + severity.
  - HistoryStore    — история START/EXIT (RAM + опционально SQLite).

Дедупликация между событийным и polling-путём — через общее множество
`_active` (pid -> create_time): кто бы ни увидел процесс первым, второй его
пропустит. Сравнение идёт по ProcessKey, а не по голому PID, поэтому
переиспользование PID между тиками не принимается за дубликат.
"""

from __future__ import annotations

import os
import queue
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

import psutil

from .backend import EventBackend
from .hashing import HashWorker
from .heuristics import RuleEngine
from .history import HistoryStore
from .identity import ProcessKey
from .models import HistoryEvent, NO_ACCESS, ProcessInfo, SignatureInfo
from .polling_backend import PollingSource
from .signature_worker import SignatureWorker

# совместимость: старый GUI/тесты ссылались на эти имена
ProcInfo = ProcessInfo
Event = HistoryEvent


class ProcessMonitor:
    def __init__(self, history: int = 20000, normalize_cpu: bool = True,
                 db_path: Optional[str] = "systema_history.sqlite3",
                 event_backend: Optional[EventBackend] = None,
                 signature_checker: Optional[Callable[[str], SignatureInfo]] = None):
        self._poll = PollingSource(normalize_cpu=normalize_cpu)
        self._rules = RuleEngine(lambda pid: self._poll.known.get(pid, ("?", 0)))

        self._hash_results: "queue.Queue[Tuple[int, str, Optional[str]]]" = queue.Queue()
        self._hash = HashWorker(lambda pid, path, digest: self._hash_results.put((pid, path, digest)))
        self._hash.start()
        self._hashed_paths: set = set()

        self._sig_results: "queue.Queue[Tuple[int, str, SignatureInfo]]" = queue.Queue()
        self._sig: Optional[SignatureWorker] = None
        if signature_checker is not None:
            self._sig = SignatureWorker(
                signature_checker, lambda pid, path, sig: self._sig_results.put((pid, path, sig)))
            self._sig.start()
        self._signed_paths: set = set()

        self.history = HistoryStore(mem_limit=history, db_path=db_path)

        self.snapshot: Dict[int, ProcessInfo] = {}
        self._active: Dict[int, float] = {}           # pid -> create_time живых процессов
        self._event_queue: "queue.Queue[tuple]" = queue.Queue()

        self.event_backend = event_backend
        # Статус — нейтральный код, а не готовая фраза: core ничего не знает
        # про язык интерфейса, перевод — забота GUI (см. i18n backend_*).
        self.event_backend_status = "disabled"     # disabled | active | unavailable
        self.event_backend_error = ""              # стабильный код причины (см. EventBackend.error)
        self.event_backend_detail = ""             # сырая техническая деталь (без перевода)
        if event_backend is not None:
            ok = event_backend.start(self._on_backend_event)
            self.event_backend_status = "active" if ok else "unavailable"
            self.event_backend_error = getattr(event_backend, "error", "") or ""
            self.event_backend_detail = getattr(event_backend, "error_detail", "") or ""

    # -------------------------------------------------- события из бэкенда

    def _on_backend_event(self, kind: str, pid: int, ppid: int, name: str,
                          exit_code: int) -> None:
        """Вызывается ИЗ ПОТОКА event-бэкенда — только кладём в очередь."""
        self._event_queue.put((time.time(), kind, pid, ppid, name, exit_code))

    # ------------------------------------------------------------- опрос

    def poll(self) -> Tuple[Dict[int, ProcessInfo], List[HistoryEvent]]:
        now = time.time()
        new_events: List[HistoryEvent] = []

        # 1) событийный бэкенд первым — он мог заметить процесс, который не
        #    доживёт до полного снимка ниже
        while True:
            try:
                ts, kind, pid, ppid, name, exit_code = self._event_queue.get_nowait()
            except queue.Empty:
                break
            new_events.extend(self._handle_backend_event(ts, kind, pid, ppid, name, exit_code))

        # 2) снимок + метрики (всегда — источник CPU/RAM/threads/handles)
        first_snapshot = self._poll.first_pass
        snap, new_pids, gone_pids = self._poll.snapshot()
        if first_snapshot:
            # Процессы, уже работавшие при запуске, считаются живыми — иначе
            # их EXIT потом никто не зафиксирует (старый монитор фиксировал).
            for pid, info in snap.items():
                self._active.setdefault(pid, info.create_time)

        # 3) эвристики + заказ хэша/подписи для новых образов в снимке
        for pid, info in snap.items():
            prev = self.snapshot.get(pid)
            if prev is not None and self._same(prev.create_time, info.create_time):
                info.sha256 = prev.sha256
                info.signature = prev.signature
            info.hits = self._rules.evaluate(info)
            self._mark_hash_unavailable(info)
            self._request_file_checks(pid, info.exe)

        # 4) diff-fallback: пропускаем процессы, которые уже обработал event-бэкенд
        for pid in new_pids:
            info = snap.get(pid)
            if info is None:
                continue
            known_ct = self._active.get(pid)
            if known_ct is not None:
                if self._same(known_ct, info.create_time):
                    continue                      # START уже записал event-бэкенд
                # тот же PID, другой create_time: прежний процесс исчез между
                # тиками незамеченным — фиксируем его EXIT, затем START нового
                new_events.append(self._exit_event(now, pid, "poll", pid_reused=True))
            self._active[pid] = info.create_time
            new_events.append(self._make_history(now, "START", info, source="poll"))
        for pid in gone_pids:
            if pid not in self._active:
                continue
            del self._active[pid]
            new_events.append(self._exit_event(now, pid, "poll"))

        # 5) применить хэши/подписи, посчитанные в фоне, к текущему снимку
        self._drain_hash_results(snap)
        self._drain_sig_results(snap)

        for ev in new_events:
            self.history.add(ev)

        self.snapshot = snap
        return snap, new_events

    @staticmethod
    def _mark_hash_unavailable(info: ProcessInfo) -> None:
        """Нет пути к образу — хэшировать нечего. Без этого поле SHA-256 вечно
        оставалось бы «считается…» (None) у процессов без доступного образа."""
        if info.sha256 is None and (not info.exe or info.exe == NO_ACCESS):
            info.sha256 = NO_ACCESS

    def _request_file_checks(self, pid: int, exe: str) -> None:
        if not exe or exe == NO_ACCESS:
            return
        if exe not in self._hashed_paths:
            self._hashed_paths.add(exe)
            self._hash.request(pid, exe)
        if self._sig is not None and exe not in self._signed_paths:
            self._signed_paths.add(exe)
            self._sig.request(pid, exe)

    def _drain_hash_results(self, snap: Dict[int, ProcessInfo]) -> None:
        while True:
            try:
                pid, path, digest = self._hash_results.get_nowait()
            except queue.Empty:
                break
            info = snap.get(pid)
            if info is not None and info.exe == path:
                info.sha256 = digest if digest is not None else NO_ACCESS

    def _drain_sig_results(self, snap: Dict[int, ProcessInfo]) -> None:
        while True:
            try:
                pid, path, sig = self._sig_results.get_nowait()
            except queue.Empty:
                break
            info = snap.get(pid)
            if info is not None and info.exe == path:
                info.signature = sig
                info.hits = self._rules.evaluate(info)   # подпись могла добавить hit

    def _same(self, a: float, b: float) -> bool:
        """Тот же ли это процесс по времени создания (0.0 = неизвестно → да)."""
        if not a or not b:
            return True
        return ProcessKey(0, a).same_process(ProcessKey(0, b))

    def _exit_event(self, ts: float, pid: int, source: str,
                    exit_code: Optional[int] = None,
                    pid_reused: bool = False) -> HistoryEvent:
        """EXIT со всем, что было известно о процессе в последнем снимке
        (путь, cmdline, пользователь, хэш, срабатывания) — сам процесс уже
        исчез, спросить его больше не у кого."""
        prev = self.snapshot.pop(pid, None)
        if prev is None:
            name, ppid = self._poll.known.get(pid, ("?", 0))
            prev = ProcessInfo(pid=pid, ppid=ppid, name=name)
        # При переиспользовании PID таблица предков уже описывает НОВЫЙ процесс —
        # достоверно известно только имя прежнего, цепочку не выдумываем.
        chain = f"{prev.name}({pid})" if pid_reused else None
        return self._make_history(ts, "EXIT", prev, source=source,
                                  exit_code=exit_code, chain=chain)

    def _handle_backend_event(self, ts: float, kind: str, pid: int, ppid: int,
                              name: str, exit_code: int) -> List[HistoryEvent]:
        events: List[HistoryEvent] = []
        if kind == "START":
            static = self._poll.static_fields_for(pid)   # читаем, пока процесс ещё жив
            ct = static.get("create_time", 0.0)
            known_ct = self._active.get(pid)
            if known_ct is not None:
                if self._same(known_ct, ct):
                    return events                        # уже учтён (polling успел раньше)
                events.append(self._exit_event(ts, pid, "wmi", pid_reused=True))   # PID переиспользован
            self._active[pid] = ct
            info = ProcessInfo(
                pid=pid, ppid=static.get("ppid") or ppid, create_time=ct,
                name=static.get("name") or name, exe=static.get("exe", ""),
                cmdline=static.get("cmdline", ""), username=static.get("username", ""))
            self._poll.known[pid] = (info.name, info.ppid)
            info.hits = self._rules.evaluate(info)
            self._mark_hash_unavailable(info)
            self._request_file_checks(pid, info.exe)
            self.snapshot[pid] = info
            events.append(self._make_history(ts, "START", info, source="wmi"))
        else:  # EXIT
            if pid not in self._active:
                return events
            del self._active[pid]
            events.append(self._exit_event(ts, pid, "wmi", exit_code=exit_code))
        return events

    def _make_history(self, ts: float, kind: str, info: ProcessInfo, source: str,
                      exit_code: Optional[int] = None,
                      chain: Optional[str] = None) -> HistoryEvent:
        return HistoryEvent(
            ts=ts, kind=kind, source=source, pid=info.pid, ppid=info.ppid,
            create_time=info.create_time, name=info.name, exe=info.exe,
            cmdline=info.cmdline, username=info.username,
            parent_chain=chain if chain is not None else self._poll.chain(info.pid),
            sha256=info.sha256, severity=info.severity,
            # (code, params) — язык не выбирается здесь; GUI рендерит через i18n
            reasons=[(h.code, h.params) for h in info.hits], exit_code=exit_code)

    # ------------------------------------------------------------- запросы

    def chain(self, pid: int, depth: int = 8) -> str:
        return self._poll.chain(pid, depth)

    def children(self, pid: int) -> List[ProcessInfo]:
        return [info for p, info in self.snapshot.items() if info.ppid == pid]

    last_error_detail = ""

    def kill(self, pid: int, force: bool = False) -> Optional[str]:
        try:
            p = psutil.Process(pid)
            p.kill() if force else p.terminate()
            return None
        except psutil.NoSuchProcess:
            return "err_gone"
        except psutil.AccessDenied:
            return "err_denied"
        except Exception as exc:  # noqa: BLE001
            self.last_error_detail = str(exc)   # сырой текст ОС — без перевода
            return "err_failed"

    def system_stats(self) -> dict:
        vm = psutil.virtual_memory()
        return {"cpu": psutil.cpu_percent(None), "ram": vm.percent,
                "used": vm.used / 2 ** 30, "total": vm.total / 2 ** 30,
                "pid": os.getpid()}

    def shutdown(self) -> None:
        if self.event_backend is not None:
            self.event_backend.stop()
        self._hash.stop()
        if self._sig is not None:
            self._sig.stop()
        self.history.close()

    @property
    def events(self):
        """Совместимость со старым UI: deque последних событий."""
        return self.history.mem
