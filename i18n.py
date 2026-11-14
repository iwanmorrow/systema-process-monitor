"""SYSTEMA Processes — локализация.

Язык по умолчанию берётся из локали ОС; переключается в тулбаре на лету.
Строки хранятся плоским словарём key -> текст, недостающий ключ возвращается как есть.
"""

from __future__ import annotations

import locale
import sys
from typing import Dict, List

LANG_ORDER: List[str] = ["ru", "en"]
LANG_LABELS: Dict[str, str] = {"ru": "Русский", "en": "English"}

STRINGS: Dict[str, Dict[str, str]] = {
    "ru": {
        "title": "SYSTEMA Processes",
        "filter": "Фильтр:",
        "view": "Вид:",
        "view_tree": "Дерево",
        "view_list": "Список",
        "only_flagged": "Только помеченные",
        "interval": "Интервал, с:",
        "pause": "Пауза",
        "theme": "Тема:",
        "theme_auto": "Авто",
        "theme_dark": "Тёмная",
        "theme_light": "Светлая",
        "language": "Язык:",
        "kill": "Завершить процесс",
        "export": "Экспорт событий",
        "tab_procs": "Процессы",
        "tab_events": "История событий",
        "col_pid": "PID",
        "col_ppid": "PPID",
        "col_name": "Имя",
        "col_user": "Пользователь",
        "col_cpu": "CPU %",
        "col_rss": "RAM, МБ",
        "col_thr": "Потоки",
        "col_started": "Запущен",
        "col_exe": "Путь",
        "col_cmd": "Command line",
        "col_time": "Время",
        "col_kind": "Событие",
        "col_flags": "Метки",
        "col_chain": "Цепочка процессов",
        "col_sev": "Уровень",
        "col_handles": "Handles",
        "col_source": "Источник",
        "col_proto": "Протокол",
        "col_laddr": "Локальный адрес",
        "col_raddr": "Удалённый адрес",
        "col_status": "Состояние",
        "starting": "Запуск…",
        "poll_error": "Ошибка опроса: {err}",
        "status": ("{sys}   |   Процессов: {procs}   |   Событий: {events}   |   "
                   "Обновлено: {time}"),
        "sys_line": "CPU {cpu:5.1f}%   RAM {ram:4.1f}% ({used:.1f}/{total:.1f} ГБ)",
        "backend_label": "Источник событий:",
        "backend_disabled": "polling (событийный backend не подключён)",
        "backend_active": "активен (WMI, near real-time)",
        "backend_unavailable": "недоступен — используется polling",
        "backend_err_pywin32-missing": "не установлен pywin32",
        "backend_err_wmi-subscribe-failed": ("не удалось подписаться на WMI process trace "
                                             "(обычно нужны права администратора)"),
        "err_failed": "Не удалось завершить процесс",
        "confirm_title": "Подтверждение",
        "confirm_kill": "Завершить процесс {name} (PID {pid})?",
        "error_title": "Ошибка",
        "err_gone": "Процесс уже завершён",
        "err_denied": "Нет доступа (нужны права администратора)",
        "no_selection": "Выберите процесс в списке, чтобы увидеть детали.",
        "sev_none": "\u2014",
        "sev_low": "LOW",
        "sev_medium": "MEDIUM",
        "sev_high": "HIGH",
        "kind_start": "СТАРТ",
        "kind_exit": "ВЫХОД",
        "reason_office-to-shell": ("{name} запущен офисным/PDF-приложением ({parent}) — "
                                   "типичный признак макро- или эксплойт-цепочки"),
        "reason_browser-to-shell": ("{name} запущен браузером ({parent}) — проверьте, не "
                                    "результат ли это скачанного файла или расширения"),
        "reason_temp-path": "Исполняемый файл запущен из временной/загрузочной папки: {exe}",
        "reason_unusual-path": "Путь к образу нетипичен для обычного ПО: {exe}",
        "reason_no-image": ("Не удалось получить путь к исполняемому файлу — процесс "
                            "завершился слишком быстро либо доступ ограничен правами"),
        "reason_suspicious-cmdline": ("Командная строка содержит признаки обфускации/скрытого "
                                      "запуска: {tokens}"),
        "reason_long-cmdline": ("Необычно длинная командная строка ({length} симв.) — "
                                "возможен встроенный payload"),
        "reason_masquerade": ("Процесс называется как системный ({name}), но запущен не из "
                              "системной папки: {exe}"),
        "reason_unsigned": "Исполняемый файл не имеет цифровой подписи",
        "reason_untrusted-signature": ("Цифровая подпись присутствует, но цепочка доверия "
                                       "не прошла проверку"),
        "src_wmi": "WMI",
        "src_poll": "poll",
        "tab_overview": "Обзор",
        "tab_security": "Безопасность / Файл",
        "tab_relationships": "Связи",
        "tab_network": "Сеть",
        "d_user": "Пользователь",
        "d_status": "Статус",
        "d_threads": "Потоков",
        "d_handles": "Handles",
        "d_started": "Запущен",
        "d_cpu_ram": "CPU / RAM",
        "d_image": "Образ",
        "d_cmd": "Команда",
        "d_chain": "Цепочка",
        "d_chain_full": "Полная цепочка",
        "d_flags": "Метки",
        "d_reasons": "Причины",
        "d_no_reasons": "Эвристики ничего не отметили.",
        "d_severity_note": ("Уровень — это максимум по сработавшим эвристикам и повод "
                            "посмотреть внимательнее, а не вердикт о вредоносности."),
        "d_hash": "SHA-256",
        "d_hash_pending": "считается…",
        "d_signature": "Подпись",
        "d_publisher": "Издатель (метаданные)",
        "d_publisher_none": "не указан",
        "d_severity": "Уровень",
        "d_parent": "Родитель",
        "d_parent_none": "неизвестен (или это корневой процесс)",
        "d_children": "Дочерние процессы",
        "d_children_none": "нет",
        "net_refresh": "Обновить",
        "net_empty": "Соединений не найдено (или нет доступа).",
        "net_hint": "Список не обновляется автоматически \u2014 нажмите «Обновить».",
        "sig_signed": "подписан, цепочка доверия пройдена",
        "sig_unsigned": "не подписан",
        "sig_untrusted": "подписан, но цепочка доверия не пройдена",
        "sig_unknown": "не проверялась",
    },
    "en": {
        "title": "SYSTEMA Processes",
        "filter": "Filter:",
        "view": "View:",
        "view_tree": "Tree",
        "view_list": "List",
        "only_flagged": "Flagged only",
        "interval": "Interval, s:",
        "pause": "Pause",
        "theme": "Theme:",
        "theme_auto": "Auto",
        "theme_dark": "Dark",
        "theme_light": "Light",
        "language": "Language:",
        "kill": "Terminate process",
        "export": "Export events",
        "tab_procs": "Processes",
        "tab_events": "Event history",
        "col_pid": "PID",
        "col_ppid": "PPID",
        "col_name": "Name",
        "col_user": "User",
        "col_cpu": "CPU %",
        "col_rss": "RAM, MB",
        "col_thr": "Threads",
        "col_started": "Started",
        "col_exe": "Image path",
        "col_cmd": "Command line",
        "col_time": "Time",
        "col_kind": "Event",
        "col_flags": "Flags",
        "col_chain": "Process chain",
        "col_sev": "Severity",
        "col_handles": "Handles",
        "col_source": "Source",
        "col_proto": "Proto",
        "col_laddr": "Local address",
        "col_raddr": "Remote address",
        "col_status": "State",
        "starting": "Starting…",
        "poll_error": "Poll error: {err}",
        "status": ("{sys}   |   Processes: {procs}   |   Events: {events}   |   "
                   "Updated: {time}"),
        "sys_line": "CPU {cpu:5.1f}%   RAM {ram:4.1f}% ({used:.1f}/{total:.1f} GB)",
        "backend_label": "Event backend:",
        "backend_disabled": "polling (no event backend wired in)",
        "backend_active": "active (WMI, near real-time)",
        "backend_unavailable": "unavailable — falling back to polling",
        "backend_err_pywin32-missing": "pywin32 is not installed",
        "backend_err_wmi-subscribe-failed": ("could not subscribe to WMI process trace "
                                             "(usually requires Administrator rights)"),
        "err_failed": "Could not terminate the process",
        "confirm_title": "Confirm",
        "confirm_kill": "Terminate {name} (PID {pid})?",
        "error_title": "Error",
        "err_gone": "Process already exited",
        "err_denied": "Access denied (administrator rights required)",
        "no_selection": "Select a process to see its details.",
        "sev_none": "\u2014",
        "sev_low": "LOW",
        "sev_medium": "MEDIUM",
        "sev_high": "HIGH",
        "kind_start": "START",
        "kind_exit": "EXIT",
        "reason_office-to-shell": ("{name} was launched by an Office/PDF application ({parent}) "
                                   "— a common sign of a macro or exploit chain"),
        "reason_browser-to-shell": ("{name} was launched by a browser ({parent}) — check "
                                    "whether this came from a downloaded file or an extension"),
        "reason_temp-path": "Executable is running from a temporary/download folder: {exe}",
        "reason_unusual-path": "Image path is unusual for regular software: {exe}",
        "reason_no-image": ("Could not get the executable path — the process exited too "
                            "quickly, or access is restricted"),
        "reason_suspicious-cmdline": ("Command line shows signs of obfuscation/hidden "
                                      "execution: {tokens}"),
        "reason_long-cmdline": ("Unusually long command line ({length} chars) — may carry "
                                "an embedded payload"),
        "reason_masquerade": ("Process is named like a system process ({name}) but is not "
                              "running from the system folder: {exe}"),
        "reason_unsigned": "Executable has no digital signature",
        "reason_untrusted-signature": ("A digital signature is present, but the trust chain "
                                       "failed verification"),
        "src_wmi": "WMI",
        "src_poll": "poll",
        "tab_overview": "Overview",
        "tab_security": "Security / File",
        "tab_relationships": "Relationships",
        "tab_network": "Network",
        "d_user": "User",
        "d_status": "Status",
        "d_threads": "Threads",
        "d_handles": "Handles",
        "d_started": "Started",
        "d_cpu_ram": "CPU / RAM",
        "d_image": "Image",
        "d_cmd": "Command",
        "d_chain": "Chain",
        "d_chain_full": "Full chain",
        "d_flags": "Flags",
        "d_reasons": "Reasons",
        "d_no_reasons": "No heuristics triggered.",
        "d_severity_note": ("The level is the highest of the heuristics that triggered — a "
                            "reason to look closer, not a verdict that the process is malicious."),
        "d_hash": "SHA-256",
        "d_hash_pending": "computing\u2026",
        "d_signature": "Signature",
        "d_publisher": "Publisher (metadata)",
        "d_publisher_none": "not set",
        "d_severity": "Severity",
        "d_parent": "Parent",
        "d_parent_none": "unknown (or this is a root process)",
        "d_children": "Child processes",
        "d_children_none": "none",
        "net_refresh": "Refresh",
        "net_empty": "No connections found (or access denied).",
        "net_hint": "This list does not auto-refresh \u2014 click Refresh.",
        "sig_signed": "signed, trust chain verified",
        "sig_unsigned": "unsigned",
        "sig_untrusted": "signed, but trust chain failed verification",
        "sig_unknown": "not checked",
    },
}

_current = "en"


def detect_system_language() -> str:
    """Язык ОС -> код из LANG_ORDER, иначе 'en'."""
    tags: List[str] = []
    try:
        if sys.platform == "win32":
            import ctypes
            lcid = ctypes.windll.kernel32.GetUserDefaultUILanguage()
            tags.append(locale.windows_locale.get(lcid, ""))
        tags.append(locale.getdefaultlocale()[0] or "")
    except Exception:  # noqa: BLE001
        pass
    for tag in tags:
        code = (tag or "").split("_")[0].split("-")[0].lower()
        if code in STRINGS:
            return code
    return "en"


def set_language(code: str) -> None:
    global _current
    if code in STRINGS:
        _current = code


def current() -> str:
    return _current


def t(key: str, **kw) -> str:
    """Перевести key на текущий язык. Если ключа нет ни в текущем языке, ни в
    английском (fallback) — вернуть сам key, чтобы пропуск перевода был виден,
    а не спрятан. Если шаблон и переданные kw не совпадают (опечатка в имени
    плейсхолдера при добавлении нового шаблона) — вернуть неотформатированный
    текст шаблона, а не уронить вызывающий код: один рассинхронизированный
    шаблон не должен обрушивать весь GUI."""
    text = STRINGS.get(_current, {}).get(key) or STRINGS["en"].get(key, key)
    if not kw:
        return text
    try:
        return text.format(**kw)
    except (KeyError, IndexError, ValueError):
        return text
