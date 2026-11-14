"""SYSTEMA Processes — эвристики.

Каждое правило возвращает HeuristicHit(code, severity, params). Текст причины
здесь НЕ формируется: core ничего не знает о языке интерфейса — это жёсткая
граница модуля. Готовую фразу собирает GUI через
``i18n.t(f"reason_{code}", **params)`` (шаблоны — в i18n.py, по одному на
каждый `code` ниже; см. tests/test_i18n_localization.py, который проверяет,
что шаблон существует для каждого кода на обоих языках).

Итоговая серьёзность процесса — максимум среди сработавших правил: не единый
вердикт «вирус / не вирус», а список конкретных наблюдений с объяснением
каждого — решение всегда остаётся за человеком.
"""

from __future__ import annotations

from typing import Callable, List, Optional, Tuple

from .models import HeuristicHit, NO_ACCESS, ProcessInfo, Severity

SHELL_LIKE = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    "bitsadmin.exe", "msbuild.exe", "installutil.exe", "wmic.exe",
    "bash", "sh", "zsh", "python", "python3",
}

UNUSUAL_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe",
    "acrord32.exe", "msaccess.exe", "visio.exe",
}

BROWSER_PARENTS = {
    "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "opera.exe", "brave.exe",
}

TEMP_MARKERS = (
    "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\downloads\\",
    "\\programdata\\", "\\users\\public\\", "/tmp/", "/dev/shm/",
)

SUSPICIOUS_PATH_MARKERS = (
    "\\appdata\\roaming\\", "\\recycle.bin\\", "\\perflogs\\",
)

# Процессам с этими именами «положено» жить в System32/SysWOW64 — если образ
# лежит не там, это либо маскарад, либо просто одноимённая сторонняя утилита;
# правило только указывает на несоответствие, не утверждает злой умысел.
KNOWN_SYSTEM_NAMES = {
    "svchost.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
    "winlogon.exe", "smss.exe", "explorer.exe", "spoolsv.exe", "taskhostw.exe",
}
SYSTEM_DIR_MARKERS = ("\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\")

ENCODED_PS_TOKENS = (
    "-enc", "-encodedcommand", "frombase64string", "downloadstring",
    "downloadfile", "invoke-expression", "iex ", "-w hidden",
    "-windowstyle hidden", "bypass", "invoke-webrequest", "net.webclient",
    "-noni ", "-nop ", "start-bitstransfer",
)

LONG_CMDLINE_THRESHOLD = 800   # неадекватно длинная командная строка


def _name(info: ProcessInfo) -> str:
    return (info.name or "").lower()


def _exe(info: ProcessInfo) -> str:
    return (info.exe or "").lower()


def _cmd(info: ProcessInfo) -> str:
    return (info.cmdline or "").lower()


def is_system_thread(info: ProcessInfo) -> bool:
    """Ядерные потоки Linux (ppid 2) и т.п. — не настоящие процессы с образом."""
    if info.pid in (0, 2, 4) or info.ppid == 2:
        return True
    return info.name.startswith("[") and info.name.endswith("]")


class RuleEngine:
    """Правила + сборка сработавших HeuristicHit для процесса.

    known_lookup(pid) -> (name, ppid) должен работать и для уже завершившихся
    процессов — иначе эвристики по родителю ломаются, как только тот выходит
    раньше ребёнка.
    """

    def __init__(self, known_lookup: Callable[[int], Tuple[str, int]]):
        self._known = known_lookup
        self._rules = [
            self._r_office_to_shell,
            self._r_browser_to_shell,
            self._r_temp_path,
            self._r_suspicious_path,
            self._r_no_image,
            self._r_encoded_cmdline,
            self._r_long_cmdline,
            self._r_masquerade,
            self._r_unsigned,
        ]

    def evaluate(self, info: ProcessInfo) -> List[HeuristicHit]:
        hits: List[HeuristicHit] = []
        for rule in self._rules:
            hit = rule(info)
            if hit:
                hits.append(hit)
        return hits

    # ------------------------------------------------------------- правила

    def _parent_name(self, info: ProcessInfo) -> str:
        return self._known(info.ppid)[0].lower() if info.ppid else ""

    def _r_office_to_shell(self, info: ProcessInfo) -> Optional[HeuristicHit]:
        parent = self._parent_name(info)
        if _name(info) in SHELL_LIKE and parent in UNUSUAL_PARENTS:
            return HeuristicHit(
                "office-to-shell", Severity.HIGH,
                {"name": info.name, "parent": parent})
        return None

    def _r_browser_to_shell(self, info: ProcessInfo) -> Optional[HeuristicHit]:
        parent = self._parent_name(info)
        if _name(info) in SHELL_LIKE and parent in BROWSER_PARENTS:
            return HeuristicHit(
                "browser-to-shell", Severity.MEDIUM,
                {"name": info.name, "parent": parent})
        return None

    def _r_temp_path(self, info: ProcessInfo) -> Optional[HeuristicHit]:
        exe = _exe(info)
        if any(m in exe for m in TEMP_MARKERS):
            return HeuristicHit(
                "temp-path", Severity.MEDIUM, {"exe": info.exe})
        return None

    def _r_suspicious_path(self, info: ProcessInfo) -> Optional[HeuristicHit]:
        exe = _exe(info)
        if any(m in exe for m in SUSPICIOUS_PATH_MARKERS):
            return HeuristicHit(
                "unusual-path", Severity.LOW, {"exe": info.exe})
        return None

    def _r_no_image(self, info: ProcessInfo) -> Optional[HeuristicHit]:
        if is_system_thread(info):
            return None
        if not info.exe or info.exe == NO_ACCESS:
            return HeuristicHit("no-image", Severity.LOW, {})
        return None

    def _r_encoded_cmdline(self, info: ProcessInfo) -> Optional[HeuristicHit]:
        if _name(info) not in SHELL_LIKE:
            return None
        cmd = _cmd(info)
        matched = sorted(t for t in ENCODED_PS_TOKENS if t in cmd)
        if matched:
            return HeuristicHit(
                "suspicious-cmdline", Severity.HIGH,
                {"tokens": ", ".join(matched)})
        return None

    def _r_long_cmdline(self, info: ProcessInfo) -> Optional[HeuristicHit]:
        length = len(info.cmdline or "")
        if length > LONG_CMDLINE_THRESHOLD:
            return HeuristicHit(
                "long-cmdline", Severity.LOW, {"length": length})
        return None

    def _r_masquerade(self, info: ProcessInfo) -> Optional[HeuristicHit]:
        name = _name(info)
        exe = _exe(info)
        if name in KNOWN_SYSTEM_NAMES and exe and exe != NO_ACCESS.lower():
            if not any(m in exe for m in SYSTEM_DIR_MARKERS):
                return HeuristicHit(
                    "masquerade", Severity.HIGH,
                    {"name": info.name, "exe": info.exe})
        return None

    def _r_unsigned(self, info: ProcessInfo) -> Optional[HeuristicHit]:
        sig = info.signature
        if not sig.checked or not info.exe or info.exe == NO_ACCESS:
            return None
        if sig.status == "unsigned":
            return HeuristicHit("unsigned", Severity.LOW, {})
        if sig.status == "untrusted":
            return HeuristicHit("untrusted-signature", Severity.MEDIUM, {})
        return None
