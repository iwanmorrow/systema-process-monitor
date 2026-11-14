"""SYSTEMA Processes — event-driven START/EXIT через WMI process trace (Windows).

Почему WMI, а не «сырой» ETW
-----------------------------
Windows даёт как минимум три пути узнавать о создании процессов без polling:

1. Raw ETW, провайдер `Microsoft-Windows-Kernel-Process` — самый богатый по
   деталям (включая путь к образу прямо в событии), но требует либо
   собственной ETW-сессии на C/C++ (нет готового стабильного биндинга под
   Python в стандартной поставке), либо стороннего пакета вроде
   `pywintrace`/`etw`, который заметно менее зрелый и поддерживаемый, чем
   pywin32. Для утилиты, которая должна быть стабильной прямо сейчас, это
   лишний источник падений ради полей, которые всё равно приходится
   перепроверять через psutil (путь мог измениться, cmdline ETW не всегда
   отдаёт полностью).
2. `Win32_ProcessStartTrace` / `Win32_ProcessStopTrace` — классы WMI,
   БЭКЕНДОМ которых как раз является тот же кернел-трейсинг, но с готовым,
   документированным COM-интерфейсом через `pywin32` (тот же пакет, что уже
   нужен для тёмного заголовка окна — новой зависимости не добавляется).
   Разрешение по времени — обычно десятки миллисекунд. Именно этот вариант
   реализован ниже.
3. Polling — то, что было раньше. Остаётся как встроенный fallback в
   core.monitor, если этот бэкенд недоступен.

Ограничения, о которых нужно знать
------------------------------------
- Подписка на trace-классы требует **прав администратора**; без них
  `ExecNotificationQuery` бросает исключение — это ожидаемо и обрабатывается
  как «бэкенд недоступен», а не как ошибка приложения.
- Событие несёт только PID/PPID/имя образа (без полного пути и cmdline) —
  за остальным сразу же обращаемся к psutil, пока процесс ещё жив; если он
  успел исчезнуть за эти миллисекунды, поля останутся `<n/a>` — это честно
  отражает реальность коротко живущих процессов, а не ошибка кода.
- Код ниже писался и проверялся статически (компиляция, структура вызовов):
  в среде разработки нет Windows, поэтому фактический прогон на реальной
  системе — с правами администратора и известными тестовыми процессами —
  должен сделать пользователь перед тем, как полагаться на этот бэкенд.
"""

from __future__ import annotations

import threading
import time
from typing import Optional

from core.backend import EventBackend, OnEvent

try:
    import pythoncom
    import win32com.client
    _WMI_OK = True
except ImportError:
    _WMI_OK = False


class WmiProcessEventBackend(EventBackend):
    available = _WMI_OK

    def __init__(self, poll_timeout_ms: int = 50):
        self._poll_timeout_ms = poll_timeout_ms
        self._thread: Optional[threading.Thread] = None
        self._stop_flag = threading.Event()
        self._on_event: Optional[OnEvent] = None
        self.error: str = "" if _WMI_OK else "pywin32-missing"
        self.error_detail: str = ""

    def start(self, on_event: OnEvent) -> bool:
        if not _WMI_OK:
            return False
        self._on_event = on_event
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        time.sleep(0.2)   # дать потоку шанс упасть на ExecNotificationQuery
        return not self.error

    def stop(self) -> None:
        self._stop_flag.set()
        if self._thread:
            self._thread.join(timeout=2)

    # --------------------------------------------------------------- поток

    def _run(self) -> None:
        pythoncom.CoInitialize()
        try:
            wmi = win32com.client.GetObject(r"winmgmts:\\.\root\cimv2")
            start_watcher = wmi.ExecNotificationQuery(
                "SELECT * FROM Win32_ProcessStartTrace")
            stop_watcher = wmi.ExecNotificationQuery(
                "SELECT * FROM Win32_ProcessStopTrace")
        except Exception as exc:  # noqa: BLE001
            self.error = "wmi-subscribe-failed"   # код; текст — в GUI (i18n)
            self.error_detail = str(exc)
            pythoncom.CoUninitialize()
            return

        while not self._stop_flag.is_set():
            for watcher, kind in ((start_watcher, "START"), (stop_watcher, "EXIT")):
                try:
                    event = watcher.NextEvent(self._poll_timeout_ms)
                except Exception:
                    # таймаут WBEM_S_TIMEDOUT — нормальная ситуация, событий
                    # не было; конкретный HRESULT не проверяем намеренно,
                    # т.к. код не был обкатан на реальном Windows
                    continue
                self._dispatch(event, kind)
        pythoncom.CoUninitialize()

    def _dispatch(self, event, kind: str) -> None:
        try:
            pid = int(event.Properties_("ProcessID").Value)
            ppid = int(event.Properties_("ParentProcessID").Value)
            name = str(event.Properties_("ProcessName").Value or "?")
            exit_code = 0
            if kind == "EXIT":
                try:
                    exit_code = int(event.Properties_("ExitStatus").Value)
                except Exception:  # noqa: BLE001
                    exit_code = 0
        except Exception:  # noqa: BLE001
            return
        if self._on_event:
            self._on_event(kind, pid, ppid, name, exit_code)
