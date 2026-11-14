"""Регрессионные тесты на границу i18n: core отдаёт языконезависимые коды и
параметры, GUI (presentation.render_reason/render_kind/event_row) превращает их в текст
на ТЕКУЩЕМ языке. Эти тесты существуют потому, что раньше core.heuristics
формировал готовый русский текст прямо внутри правил — при английском
интерфейсе он не переводился никогда. Тесты здесь проверяют именно класс этой
ошибки, а не конкретную старую реализацию, чтобы не допустить повторения.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import i18n
import presentation
from core.heuristics import RuleEngine
from core.models import HistoryEvent, NO_ACCESS, ProcessInfo, Severity, SignatureInfo

# Сценарии, каждый из которых детерминированно включает ровно одно известное
# правило — используются, чтобы СОБРАТЬ множество кодов, которые реально
# производит RuleEngine, а не поддерживать отдельный задублированный список
# вручную (поддерживать две копии списка кодов — ровно то, из-за чего легко
# забыть добавить перевод для нового правила).
_KNOWN = {1: ("WINWORD.EXE", 0)}


def _trigger_scenarios():
    engine = RuleEngine(lambda pid: _KNOWN.get(pid, ("?", 0)))
    scenarios = [
        ProcessInfo(pid=2, ppid=1, name="powershell.exe",
                   exe="C:\\Windows\\System32\\powershell.exe"),                       # office-to-shell
        ProcessInfo(pid=3, ppid=0, name="cmd.exe", exe="C:\\Windows\\System32\\cmd.exe"),
        ProcessInfo(pid=4, name="x.exe", exe="C:\\Users\\a\\AppData\\Local\\Temp\\x.exe"),
        ProcessInfo(pid=5, name="x.exe", exe="C:\\Users\\a\\AppData\\Roaming\\x.exe"),
        ProcessInfo(pid=6, name="mystery", exe=NO_ACCESS),
        ProcessInfo(pid=7, name="powershell.exe", cmdline="powershell -enc AAAA"),
        ProcessInfo(pid=8, name="x.exe", cmdline="x " + "a" * 900),
        ProcessInfo(pid=9, name="svchost.exe", exe="C:\\Users\\a\\Desktop\\svchost.exe"),
    ]
    signed_unsigned = ProcessInfo(pid=10, name="tool.exe", exe="C:\\tools\\tool.exe")
    signed_unsigned.signature = SignatureInfo(status="unsigned", checked=True)
    scenarios.append(signed_unsigned)
    signed_untrusted = ProcessInfo(pid=11, name="tool.exe", exe="C:\\tools\\tool.exe")
    signed_untrusted.signature = SignatureInfo(status="untrusted", checked=True)
    scenarios.append(signed_untrusted)

    browser_known = {20: ("chrome.exe", 0)}
    browser_engine = RuleEngine(lambda pid: browser_known.get(pid, ("?", 0)))
    browser_scenario = ProcessInfo(pid=21, ppid=20, name="cmd.exe",
                                   exe="C:\\Windows\\System32\\cmd.exe")

    codes_to_hits = {}
    for info in scenarios:
        for hit in engine.evaluate(info):
            codes_to_hits.setdefault(hit.code, hit)
    for hit in browser_engine.evaluate(browser_scenario):
        codes_to_hits.setdefault(hit.code, hit)
    return codes_to_hits


EXPECTED_CODES = {
    "office-to-shell", "browser-to-shell", "temp-path", "unusual-path",
    "no-image", "suspicious-cmdline", "long-cmdline", "masquerade",
    "unsigned", "untrusted-signature",
}


def test_trigger_scenarios_cover_all_known_rule_codes():
    """Подстраховка для самого набора сценариев выше: если кто-то добавит новое
    правило в core/heuristics.py и не добавит сценарий здесь, следующий тест
    (i18n-покрытие) её просто не увидит и молча пропустит — эта проверка делает
    такой пробел явным, а не тихим."""
    codes = set(_trigger_scenarios())
    assert codes == EXPECTED_CODES, (
        f"сценарии не покрывают все коды: отсутствуют {EXPECTED_CODES - codes}, "
        f"неизвестные {codes - EXPECTED_CODES}")


def test_every_rule_code_has_ru_and_en_template():
    for code in EXPECTED_CODES:
        key = f"reason_{code}"
        assert key in i18n.STRINGS["ru"], f"нет RU-шаблона для {code}"
        assert key in i18n.STRINGS["en"], f"нет EN-шаблона для {code}"


def test_every_rule_reason_actually_differs_between_languages():
    """Шаблон может формально существовать, но случайно совпадать со значением
    по умолчанию (например, при копипасте) — так язык технически присутствует,
    но перевода фактически нет. Эта проверка ловит именно такую тихую порчу."""
    hits = _trigger_scenarios()
    for code, hit in hits.items():
        i18n.set_language("en")
        en_text = presentation.render_reason(code, hit.params)
        i18n.set_language("ru")
        ru_text = presentation.render_reason(code, hit.params)
        assert en_text != f"reason_{code}", f"{code}: EN вернул сам ключ — перевод отсутствует"
        assert ru_text != f"reason_{code}", f"{code}: RU вернул сам ключ — перевод отсутствует"
        assert en_text != ru_text, f"{code}: EN и RU совпадают — перевод не настоящий"


def test_kind_start_exit_localized_and_differ_by_language():
    i18n.set_language("en")
    en_start, en_exit = presentation.render_kind("START"), presentation.render_kind("EXIT")
    i18n.set_language("ru")
    ru_start, ru_exit = presentation.render_kind("START"), presentation.render_kind("EXIT")
    assert en_start != ru_start
    assert en_exit != ru_exit
    assert en_start != en_exit
    assert ru_start != ru_exit


def _make_history_event(code: str, params: dict) -> HistoryEvent:
    return HistoryEvent(
        ts=0.0, kind="START", source="poll", pid=99, ppid=1, create_time=0.0,
        name="evil.exe", exe="C:\\Temp\\evil.exe", cmdline="evil.exe",
        username="bob", parent_chain="explorer.exe(1) \u2192 evil.exe(99)",
        sha256=None, severity=Severity.HIGH, reasons=[(code, params)])


def test_event_history_row_renders_in_current_language():
    """Регрессия на конкретный баг: строка в «Истории событий» раньше
    форматировалась один раз в момент вставки и навсегда оставалась на том
    языке — переключение RU/EN не меняло уже вставленные строки."""
    ev = _make_history_event("temp-path", {"exe": "C:\\Temp\\evil.exe"})

    i18n.set_language("en")
    values_en, _tag = presentation.event_row(ev)
    i18n.set_language("ru")
    values_ru, _tag = presentation.event_row(ev)

    # индекс 1 = kind, индекс -1 = reasons (см. presentation.event_row)
    assert values_en[1] != values_ru[1]            # START/EXIT локализован
    assert values_en[-1] != values_ru[-1]           # текст причины локализован
    assert "Temp" in values_en[-1] or "C:\\Temp" in values_en[-1]
    assert "evil.exe" in values_ru[-1]


def test_event_history_never_mixes_languages_within_one_render():
    """На одном языке все поля одной строки должны быть на этом языке —
    не должно быть так, что kind перевёлся, а reasons остались на другом."""
    ev = _make_history_event("suspicious-cmdline", {"tokens": "-enc"})
    for lang in ("ru", "en"):
        i18n.set_language(lang)
        values, _tag = presentation.event_row(ev)
        kind_text, reasons_text = values[1], values[-1]
        # счастливый инвариант для этих двух конкретных шаблонов: раз язык
        # совпадает, обе строки должны либо обе содержать кириллицу, либо
        # обе не содержать — иначе кто-то из путей рендера не переключился
        import re
        has_cyr_kind = bool(re.search(r"[а-яА-ЯёЁ]", kind_text))
        has_cyr_reasons = bool(re.search(r"[а-яА-ЯёЁ]", reasons_text))
        assert has_cyr_kind == (lang == "ru")
        assert has_cyr_reasons == (lang == "ru")


def test_missing_translation_key_is_visible_not_silently_dropped():
    """Если ключа нет вовсе ни в текущем языке, ни в английском fallback —
    i18n.t должен вернуть сам ключ (чтобы пропуск был виден разработчику и
    тестеру), а не тихую пустую строку."""
    i18n.set_language("ru")
    assert i18n.t("this_key_does_not_exist_anywhere") == "this_key_does_not_exist_anywhere"


def test_mismatched_params_do_not_crash_rendering():
    """Параметры, не совпадающие с плейсхолдерами шаблона (опечатка при
    добавлении нового правила), не должны ронять рендер — i18n.t должен
    выдать неотформатированный шаблон, а не бросить исключение наружу."""
    i18n.set_language("en")
    # у reason_temp-path плейсхолдер {exe}, передаём заведомо другое имя
    result = presentation.render_reason("temp-path", {"wrong_name": "value"})
    assert isinstance(result, str)
    assert result   # не упало и не вернуло пустую строку


# ------------------------------------------------------------------ полнота ключей

def _referenced_keys():
    """Ключи, на которые реально ссылается GUI-код: литералы в i18n.t(...),
    значения таблиц SEV_KEYS/SIG_KEYS и ключи колонок из app.py (разбор через
    ast — чтобы тест не требовал tkinter и не импортировал app)."""
    import ast
    root = Path(__file__).resolve().parents[1]
    keys = set(presentation.SEV_KEYS.values()) | set(presentation.SIG_KEYS.values())
    keys |= {"kind_start", "kind_exit", "src_wmi", "src_poll"}
    for fname in ("app.py", "presentation.py"):
        tree = ast.parse((root / fname).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "t" and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)):
                keys.add(node.args[0].value)
            if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id in ("PROC_COLUMNS", "EVENT_COLUMNS", "NET_COLUMNS")
                    for t in node.targets):
                for elt in node.value.elts:
                    keys.add(elt.elts[1].value)
    return keys


def test_every_referenced_key_exists_in_both_languages():
    missing = {}
    for lang in ("ru", "en"):
        absent = sorted(k for k in _referenced_keys() if k not in i18n.STRINGS[lang])
        if absent:
            missing[lang] = absent
    assert not missing, f"отсутствуют ключи перевода: {missing}"


def test_ru_and_en_have_identical_key_sets_and_placeholders():
    import string
    ru, en = i18n.STRINGS["ru"], i18n.STRINGS["en"]
    assert set(ru) == set(en), f"разные наборы ключей: {set(ru) ^ set(en)}"

    def fields(text):
        return {f for _, f, _, _ in string.Formatter().parse(text) if f}

    for key in ru:
        assert fields(ru[key]) == fields(en[key]), (
            f"{key}: плейсхолдеры RU {fields(ru[key])} != EN {fields(en[key])}")


# ------------------------------------------------------- граница core / i18n

def _non_docstring_string_literals(path):
    import ast
    tree = ast.parse(path.read_text(encoding="utf-8"))
    doc_ids = set()
    for node in ast.walk(tree):
        if (isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and node.body and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)):
            doc_ids.add(id(node.body[0].value))
    for node in ast.walk(tree):
        if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                and id(node) not in doc_ids):
            yield node.lineno, node.value


def test_core_and_windows_contain_no_cyrillic_runtime_strings():
    """Постоянная версия репозиторного поиска: ни одна строка, которая может
    стать значением в рантайме (не докстринг и не комментарий), в core/ и
    windows/ не содержит кириллицы. Весь русский текст живёт в i18n.py."""
    import re
    root = Path(__file__).resolve().parents[1]
    cyr = re.compile(r"[а-яА-ЯёЁ]")
    offenders = []
    for sub in ("core", "windows"):
        for path in sorted((root / sub).glob("*.py")):
            for lineno, value in _non_docstring_string_literals(path):
                if cyr.search(value):
                    offenders.append(f"{sub}/{path.name}:{lineno}: {value[:60]!r}")
    assert not offenders, "кириллица в runtime-строках core/windows:\n" + "\n".join(offenders)


def test_core_and_windows_contain_no_english_sentences_either():
    """То же для английской «прозы»: граница i18n работает в обе стороны —
    английское предложение в core так же недопустимо, как русское (иначе в
    русском интерфейсе появится английский текст). Разрешены только
    технические токены: SQL, ключевые слова детекции."""
    import re
    root = Path(__file__).resolve().parents[1]
    sentence = re.compile(r"\b[A-Za-z]{2,}\s+[A-Za-z]{2,}\s+[A-Za-z]{2,}\b")
    allowed_prefixes = ("SELECT", "INSERT", "CREATE", "\nCREATE")
    offenders = []
    for sub in ("core", "windows"):
        for path in sorted((root / sub).glob("*.py")):
            for lineno, value in _non_docstring_string_literals(path):
                if value.startswith(allowed_prefixes) or "TABLE" in value:
                    continue
                if sentence.search(value):
                    offenders.append(f"{sub}/{path.name}:{lineno}: {value[:60]!r}")
    assert not offenders, "английская проза в core/windows:\n" + "\n".join(offenders)


def test_wmi_backend_reports_stable_error_code_with_translations():
    from windows.wmi_events import WmiProcessEventBackend
    backend = WmiProcessEventBackend()
    if backend.available:
        return   # на Windows с pywin32 этот путь недостижим — проверяется там вручную
    assert backend.start(lambda *a: None) is False
    assert backend.error == "pywin32-missing"
    for lang in ("ru", "en"):
        assert f"backend_err_{backend.error}" in i18n.STRINGS[lang]


def test_known_backend_error_codes_all_have_translations():
    for code in ("pywin32-missing", "wmi-subscribe-failed"):
        for lang in ("ru", "en"):
            assert f"backend_err_{code}" in i18n.STRINGS[lang]


def test_monitor_kill_returns_stable_error_codes_not_text():
    from core.monitor import ProcessMonitor
    mon = ProcessMonitor(db_path=None)
    try:
        code = mon.kill(2 ** 22 + 12345)   # заведомо несуществующий PID
        assert code == "err_gone"
        for lang in ("ru", "en"):
            assert code in i18n.STRINGS[lang]
            assert "err_failed" in i18n.STRINGS[lang]
    finally:
        mon.shutdown()
