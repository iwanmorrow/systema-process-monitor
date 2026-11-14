"""SYSTEMA Processes — модели данных ядра.

Ничего здесь не знает про Windows, tkinter или конкретный способ получения
данных — только формы данных, которыми ядро обменивается с GUI.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

NO_ACCESS = "<n/a>"   # значение недоступно (нет прав / процесс исчез)
UNKNOWN = "<?>"        # источник события не предоставил это поле


class Severity(str, Enum):
    """Не «вирус / не вирус» — уровень внимания, который заслуживает процесс."""

    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @property
    def rank(self) -> int:
        return {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}[self.value]

    @staticmethod
    def max_of(items) -> "Severity":
        best = Severity.NONE
        for s in items:
            if s.rank > best.rank:
                best = s
        return best


@dataclass(frozen=True)
class HeuristicHit:
    """Одно сработавшее правило: код + серьёзность + параметры для объяснения.

    Сам текст причины НЕ хранится здесь: core ничего не знает о языке
    интерфейса. Готовую фразу собирает GUI через
    ``i18n.t(f"reason_{code}", **params)`` — шаблоны лежат в i18n.py.
    """

    code: str
    severity: Severity
    params: Dict[str, object] = field(default_factory=dict)


@dataclass
class SignatureInfo:
    """Результат проверки Authenticode. status: signed/unsigned/untrusted/unknown."""

    status: str = "unknown"
    signer: str = ""
    checked: bool = False


@dataclass
class NetConnection:
    proto: str
    laddr: str
    lport: int
    raddr: str
    rport: int
    status: str


@dataclass
class ProcessInfo:
    pid: int
    ppid: int = 0
    create_time: float = 0.0
    name: str = "?"
    exe: str = ""
    cmdline: str = ""
    username: str = ""
    cpu: float = 0.0
    rss: int = 0
    threads: int = 0
    handles: int = -1                       # -1 = недоступно на этой платформе
    status: str = ""
    sha256: Optional[str] = None             # None = ещё не посчитан
    signature: SignatureInfo = field(default_factory=SignatureInfo)
    hits: List[HeuristicHit] = field(default_factory=list)

    @property
    def rss_mb(self) -> float:
        return self.rss / (1024 * 1024)

    @property
    def started(self) -> str:
        if not self.create_time:
            return ""
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.create_time))

    @property
    def severity(self) -> Severity:
        return Severity.max_of(h.severity for h in self.hits) if self.hits else Severity.NONE

    @property
    def flags(self) -> List[str]:
        """Короткие коды сработавших правил (для GUI-совместимости и CSV)."""
        return [h.code for h in self.hits]


@dataclass
class HistoryEvent:
    """Запись START/EXIT. Снимок того, что было известно В МОМЕНТ события —
    процесс мог исчезнуть секунду спустя, история всё равно его помнит."""

    ts: float
    kind: str                                # START | EXIT
    source: str                              # 'wmi' | 'poll' — кто заметил событие
    pid: int
    ppid: int
    create_time: float
    name: str
    exe: str
    cmdline: str
    username: str
    parent_chain: str
    sha256: Optional[str] = None
    severity: Severity = Severity.NONE
    # (code, params) — та же языконезависимая форма, что и HeuristicHit;
    # рендерится в текст на стороне GUI, а не здесь.
    reasons: List[Tuple[str, Dict[str, object]]] = field(default_factory=list)
    exit_code: Optional[int] = None

    @property
    def time_str(self) -> str:
        return time.strftime("%H:%M:%S", time.localtime(self.ts))
