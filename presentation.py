"""SYSTEMA Processes — слой представления (без tkinter).

Здесь (code, params) и перечисления из core превращаются в текст на текущем
языке интерфейса. Модуль намеренно не импортирует tkinter: его должно быть
можно проверить в тестах на машине без дисплея и без python3-tk, а app.py
остаётся чистым GUI без правил форматирования.

Граница i18n: core отдаёт только коды и структурированные данные; весь текст
для человека собирается здесь и в i18n.py.
"""

from __future__ import annotations

import i18n
from core.models import HistoryEvent, Severity

SEV_KEYS = {Severity.NONE: "sev_none", Severity.LOW: "sev_low",
            Severity.MEDIUM: "sev_medium", Severity.HIGH: "sev_high"}
SEV_TAGS = {Severity.LOW: "sev_low", Severity.MEDIUM: "sev_medium", Severity.HIGH: "sev_high"}
SIG_KEYS = {"signed": "sig_signed", "unsigned": "sig_unsigned",
            "untrusted": "sig_untrusted", "unknown": "sig_unknown"}


def render_reason(code: str, params: dict) -> str:
    """Единственное место, где (code, params) из core превращается в текст на
    текущем языке интерфейса. Модульная функция (не метод) — чтобы её можно
    было проверить в тестах без создания живого окна Tk. i18n.t() уже сам
    деградирует, если шаблон для code не найден или params не совпадают с
    плейсхолдерами (см. i18n.t): в этом случае вернётся неотформатированный
    шаблон, а не исключение, так что рендер истории/деталей не падает даже
    на рассинхронизированном шаблоне."""
    return i18n.t(f"reason_{code}", **params)


def render_kind(kind: str) -> str:
    """START/EXIT -> локализованная подпись для отображения (не для CSV —
    там код события остаётся машинно-читаемым и языконезависимым)."""
    return i18n.t("kind_start" if kind == "START" else "kind_exit")


def event_row(e: HistoryEvent) -> tuple:
    """(значения_строки, тег) для одной записи истории — на ТЕКУЩЕМ языке.

    Единственное место, где HistoryEvent превращается в строку таблицы.
    Модульная функция (не метод App), не требующая живого окна Tk — поэтому
    её можно проверить в тестах без дисплея. Используется и при добавлении
    новых событий (_append_events), и при полной перерисовке дерева после
    смены языка (_rebuild_event_tree): у обоих путей рендера гарантированно
    совпадает результат, не может возникнуть отдельная, забытая при переводе
    копия форматирования.
    """
    tag = SEV_TAGS.get(e.severity)
    if tag is None:
        tag = "start" if e.kind == "START" else "exit"
    src = i18n.t("src_wmi") if e.source == "wmi" else i18n.t("src_poll")
    reasons_text = "; ".join(render_reason(code, params) for code, params in e.reasons)
    values = (e.time_str, render_kind(e.kind), src, i18n.t(SEV_KEYS[e.severity]),
              e.pid, e.name, e.username, e.parent_chain, reasons_text)
    return values, tag
