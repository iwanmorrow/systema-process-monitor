"""SYSTEMA Processes — снимки процессов через psutil (polling).

Всегда активен и остаётся ЕДИНСТВЕННЫМ источником CPU/RAM/потоков/handles —
событийные механизмы ОС такую динамику не поставляют в принципе. Также умеет
строить diff (START/EXIT) самостоятельно: это резервный путь, когда
event-backend недоступен (нет прав администратора, не Windows, WMI не смог
подписаться) — деградация только по задержке (до одного тика), не по составу
данных.

Идентификация процессов — через ProcessKey (core.identity): кэш статических
полей ключится парой (pid, create_time), а не голым PID, чтобы переиспользование
PID операционной системой не смешивало старый процесс с новым в одной записи.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

import psutil

from .identity import ProcessKey
from .models import NO_ACCESS, ProcessInfo

_UNKNOWN_STATIC = {"exe": "", "cmdline": "", "username": "", "create_time": 0.0,
                   "ppid": 0, "name": "?"}


class PollingSource:
    def __init__(self, normalize_cpu: bool = True):
        self._proc_cache: Dict[ProcessKey, psutil.Process] = {}
        self._static: Dict[int, dict] = {}            # pid -> статические поля
        self._prev_keys: Dict[int, float] = {}          # pid -> create_time (прошлый тик)
        self.known: Dict[int, Tuple[str, int]] = {}      # pid -> (name, ppid), включая мёртвых
        self.first_pass = True
        self._ncpu = psutil.cpu_count() or 1
        self.normalize_cpu = normalize_cpu

    # ---------------------------------------------------------- внутреннее

    def _static_fields(self, p: psutil.Process) -> dict:
        data = dict(_UNKNOWN_STATIC)
        try:
            with p.oneshot():
                data["name"] = p.name()
                data["ppid"] = p.ppid()
                data["create_time"] = p.create_time()
                try:
                    data["exe"] = p.exe() or ""
                except (psutil.AccessDenied, OSError):
                    data["exe"] = NO_ACCESS
                try:
                    cl = p.cmdline()
                    data["cmdline"] = " ".join(cl) if cl else ""
                except (psutil.AccessDenied, OSError):
                    data["cmdline"] = NO_ACCESS
                try:
                    data["username"] = p.username() or ""
                except (psutil.AccessDenied, KeyError, OSError):
                    data["username"] = NO_ACCESS
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return data

    def static_fields_for(self, pid: int) -> dict:
        """Публичный доступ — используется event-бэкендом сразу на START,
        пока процесс ещё жив и его образ/cmdline можно прочитать."""
        try:
            p = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return dict(_UNKNOWN_STATIC)
        data = self._static_fields(p)
        self._static[pid] = data
        key = ProcessKey(pid, data.get("create_time", 0.0))
        self._proc_cache[key] = p
        try:
            p.cpu_percent(None)
        except Exception:  # noqa: BLE001
            pass
        return data

    def chain(self, pid: int, depth: int = 8) -> str:
        parts: List[str] = []
        seen = set()
        cur = pid
        while cur and cur not in seen and len(parts) < depth:
            seen.add(cur)
            name, ppid = self.known.get(cur, ("?", 0))
            parts.append(f"{name}({cur})")
            cur = ppid
        return " \u2192 ".join(reversed(parts))

    # --------------------------------------------------------------- опрос

    def snapshot(self) -> Tuple[Dict[int, ProcessInfo], List[int], List[int]]:
        """Один опрос: (снимок, pid'ы новых процессов, pid'ы исчезнувших)."""
        snap: Dict[int, ProcessInfo] = {}
        seen: Dict[int, float] = {}

        for p in psutil.process_iter(attrs=None):
            pid = p.pid
            try:
                ct = p.create_time()
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                ct = 0.0

            key = ProcessKey(pid, ct)
            cached = self._proc_cache.get(key)
            if cached is None:
                # либо новый pid, либо pid переиспользован
                self._proc_cache = {k: v for k, v in self._proc_cache.items() if k.pid != pid}
                self._proc_cache[key] = p
                self._static[pid] = self._static_fields(p)
                cached = p
                try:
                    cached.cpu_percent(None)   # прайминг счётчика
                except Exception:  # noqa: BLE001
                    pass

            st = self._static.get(pid, _UNKNOWN_STATIC)
            info = ProcessInfo(
                pid=pid, ppid=st.get("ppid", 0), create_time=st.get("create_time", ct),
                name=st.get("name", "?"), exe=st.get("exe", ""),
                cmdline=st.get("cmdline", ""), username=st.get("username", ""))
            try:
                with cached.oneshot():
                    cpu = cached.cpu_percent(None)
                    info.cpu = cpu / self._ncpu if self.normalize_cpu else cpu
                    info.rss = cached.memory_info().rss
                    info.threads = cached.num_threads()
                    info.status = cached.status()
                    num_handles = getattr(cached, "num_handles", None)
                    info.handles = num_handles() if num_handles else -1
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                pass

            self.known[pid] = (info.name, info.ppid)
            snap[pid] = info
            seen[pid] = info.create_time

        new_pids: List[int] = []
        gone_pids: List[int] = []
        if not self.first_pass:
            for pid, ct in seen.items():
                prev_ct = self._prev_keys.get(pid)
                # "новый" = не видели этот PID раньше ИЛИ видели, но с другим
                # create_time (переиспользование PID) — тот же критерий
                # идентичности, что и везде в core (ProcessKey.same_process),
                # а не отдельный, незасвисимо подобранный допуск здесь.
                if prev_ct is None or not ProcessKey(pid, prev_ct).same_process(ProcessKey(pid, ct)):
                    new_pids.append(pid)
            for pid in self._prev_keys:
                if pid not in seen:
                    gone_pids.append(pid)

        self._prev_keys = seen
        self.first_pass = False

        # подрезать словарь мёртвых pid, чтобы не расти бесконечно
        if len(self.known) > 20000:
            for pid in list(self.known.keys()):
                if pid not in seen:
                    self.known.pop(pid, None)

        return snap, new_pids, gone_pids
