"""SYSTEMA Processes — интерфейс event-driven бэкенда.

Реализация узнаёт о создании/завершении процессов «сразу» — без ожидания
следующего polling-тика — и не поставляет CPU/RAM/threads: эти метрики
системные события ОС не несут, для них всегда работает polling.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable

# on_event(kind, pid, ppid, name, exit_code)
OnEvent = Callable[[str, int, int, str, int], None]


class EventBackend(ABC):
    available: bool = False   # можно ли вообще использовать на этой машине

    @abstractmethod
    def start(self, on_event: OnEvent) -> bool:
        """Запустить подписку. Вернуть True при успехе, False — см. .error."""

    @abstractmethod
    def stop(self) -> None:
        """Остановить фоновый поток/подписку и освободить ресурсы."""

    # Стабильный код причины недоступности ("" — ошибок нет), НЕ текст для
    # человека: язык выбирает GUI через i18n (ключ backend_err_<код>).
    error: str = ""
    # Сырая техническая деталь (текст исключения ОС) — динамические данные
    # внешней системы, не переводится и показывается как есть.
    error_detail: str = ""
