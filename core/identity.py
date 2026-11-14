"""SYSTEMA Processes — идентификация процессов.

ОС переиспользует PID: закрывшийся процесс 4242 через минуту может стать
совсем другим процессом с тем же номером. Единственный надёжный
идентификатор — пара (PID, время создания). Всё ядро строится вокруг этого
ключа, а не вокруг голого PID.
"""

from __future__ import annotations

from dataclasses import dataclass

# Разные источники (psutil, WMI) отдают create_time с разной точностью
# округления — сравниваем с запасом, а не побитово.
EPS = 0.05


@dataclass(frozen=True, order=True)
class ProcessKey:
    """Уникальный идентификатор процесса: PID + время создания (эпоха, сек)."""

    pid: int
    create_time: float

    def same_process(self, other: "ProcessKey") -> bool:
        return self.pid == other.pid and abs(self.create_time - other.create_time) < EPS

    def __str__(self) -> str:  # для логов и истории
        return f"{self.pid}@{self.create_time:.3f}"
