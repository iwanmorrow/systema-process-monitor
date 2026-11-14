import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.heuristics import RuleEngine
from core.models import NO_ACCESS, ProcessInfo, Severity, SignatureInfo


def engine(known: dict) -> RuleEngine:
    return RuleEngine(lambda pid: known.get(pid, ("?", 0)))


def test_office_to_shell_is_high():
    known = {100: ("WINWORD.EXE", 1)}
    info = ProcessInfo(pid=200, ppid=100, name="powershell.exe", exe="C:\\Windows\\System32\\powershell.exe")
    hits = engine(known).evaluate(info)
    codes = {h.code for h in hits}
    assert "office-to-shell" in codes
    sev = Severity.max_of(h.severity for h in hits)
    assert sev == Severity.HIGH


def test_clean_system_process_has_no_hits():
    known = {1: ("services.exe", 0)}
    info = ProcessInfo(pid=50, ppid=1, name="svchost.exe",
                       exe="C:\\Windows\\System32\\svchost.exe", cmdline="svchost.exe -k netsvcs")
    hits = engine({}).evaluate(info)
    assert hits == []


def test_temp_path_flagged_medium():
    info = ProcessInfo(pid=10, name="update.exe",
                       exe="C:\\Users\\bob\\AppData\\Local\\Temp\\update.exe")
    hits = engine({}).evaluate(info)
    assert any(h.code == "temp-path" and h.severity == Severity.MEDIUM for h in hits)


def test_encoded_powershell_is_high_and_lists_tokens_in_params():
    info = ProcessInfo(pid=11, name="powershell.exe",
                       cmdline="powershell.exe -enc SGVsbG8gV29ybGQ=")
    hits = engine({}).evaluate(info)
    hit = next(h for h in hits if h.code == "suspicious-cmdline")
    assert hit.severity == Severity.HIGH
    # core отдаёт структурированные params, а не готовый текст на каком-то
    # языке — рендер в человеческую фразу делает GUI через i18n (см.
    # tests/test_i18n_localization.py)
    assert "-enc" in hit.params["tokens"]


def test_heuristic_hit_carries_no_rendered_text():
    """core не должен формировать готовый текст причины — только код и
    параметры. Если это когда-нибудь вернётся (например, кто-то добавит
    reason= в HeuristicHit), это и есть путь для утечки русского текста в
    английский интерфейс, о котором просили не забывать."""
    from core.models import HeuristicHit
    assert not hasattr(HeuristicHit("x", Severity.LOW, {}), "reason")


def test_masquerade_svchost_outside_system32():
    info = ProcessInfo(pid=12, name="svchost.exe", exe="C:\\Users\\bob\\Desktop\\svchost.exe")
    hits = engine({}).evaluate(info)
    assert any(h.code == "masquerade" and h.severity == Severity.HIGH for h in hits)


def test_no_image_not_raised_for_kernel_thread():
    info = ProcessInfo(pid=2, ppid=0, name="kthreadd", exe="")
    hits = engine({}).evaluate(info)
    assert not any(h.code == "no-image" for h in hits)


def test_no_image_raised_for_real_process_without_exe():
    info = ProcessInfo(pid=999, ppid=1, name="mystery", exe=NO_ACCESS)
    hits = engine({}).evaluate(info)
    assert any(h.code == "no-image" for h in hits)


def test_unsigned_only_fires_after_signature_checked():
    info = ProcessInfo(pid=13, name="tool.exe", exe="C:\\tools\\tool.exe")
    hits = engine({}).evaluate(info)
    assert not any(h.code == "unsigned" for h in hits)   # ещё не проверялась

    info.signature = SignatureInfo(status="unsigned", checked=True)
    hits = engine({}).evaluate(info)
    assert any(h.code == "unsigned" and h.severity == Severity.LOW for h in hits)


def test_severity_is_max_not_sum():
    known = {1: ("WINWORD.EXE", 0)}
    info = ProcessInfo(pid=2, ppid=1, name="powershell.exe",
                       exe="C:\\Users\\x\\AppData\\Local\\Temp\\powershell.exe",
                       cmdline="powershell -enc AAAA")
    hits = engine(known).evaluate(info)
    assert len(hits) >= 2   # office-to-shell (HIGH) + temp-path (MEDIUM) + cmdline (HIGH)
    assert Severity.max_of(h.severity for h in hits) == Severity.HIGH
