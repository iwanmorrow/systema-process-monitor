"""SYSTEMA Processes — проверка Authenticode-подписи (Windows).

`WinVerifyTrust` даёт факт: подписан ли файл и доверяет ли Windows цепочке
сертификатов (вызывается с WTD_UI_NONE — без диалогов пользователю).

Имя издателя из цепочки сертификатов сознательно НЕ извлекается через
`CryptQueryObject` + `CertGetNameString` — это отдельная связка вызовов
Crypt32, разбор ASN.1-полей в которой невозможно надёжно проверить без
Windows под рукой; ошибка в парсинге здесь хуже, чем честное «неизвестно».
Вместо этого `signer` берётся из метаданных версии файла
(VERSIONINFO / CompanyName) — это НЕ криптографическое доказательство
личности издателя, а информация «как её видит Проводник», и подписана в UI
соответствующим образом (см. i18n-строку d_publisher).

Статус ограничения: код ниже написан и статически проверен (компиляция,
структуры ctypes соответствуют документации WinTrust.h), но не прогонялся
на реальном Windows — в среде разработки его нет. Перед тем как полагаться
на вердикт «unsigned»/«untrusted» в реальном расследовании, стоит сверить
поведение на паре заведомо подписанных и неподписанных файлов.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes

from core.models import SignatureInfo

try:
    import win32api
    _VERSIONINFO_OK = True
except ImportError:
    _VERSIONINFO_OK = False

_WINTRUST_AVAILABLE = hasattr(ctypes, "WinDLL")

# WINTRUST_ACTION_GENERIC_VERIFY_V2 = {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
_ACTION_GUID_FIELDS = (
    0x00AAC56B, 0xCD44, 0x11D0,
    (0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2

# TRUST_E_NOSIGNATURE (0x800B0100) как знаковый int32, который возвращает
# WinVerifyTrust (LONG). Другие ненулевые коды (истёкший/отозванный
# сертификат, несовпадение хэша и т.д.) намеренно сворачиваются в один
# статус "untrusted" — точное различение требует таблицы констант, которую
# не на чем было сверить.
_TRUST_E_NOSIGNATURE = -2146762496


class _GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]


class _WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
                ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.c_void_p)]


class _WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(_WINTRUST_FILE_INFO)),
        ("dwStateAction", wintypes.DWORD), ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR), ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
    ]


def _make_guid() -> _GUID:
    d1, d2, d3, d4 = _ACTION_GUID_FIELDS
    return _GUID(d1, d2, d3, (ctypes.c_ubyte * 8)(*d4))


def _verify_trust(path: str) -> str:
    """Вернуть 'signed' | 'unsigned' | 'untrusted' | 'unknown'."""
    if not _WINTRUST_AVAILABLE:
        return "unknown"
    try:
        wintrust = ctypes.WinDLL("wintrust.dll")
    except OSError:
        return "unknown"

    file_info = _WINTRUST_FILE_INFO(
        cbStruct=ctypes.sizeof(_WINTRUST_FILE_INFO), pcwszFilePath=path,
        hFile=None, pgKnownSubject=None)
    data = _WINTRUST_DATA(
        cbStruct=ctypes.sizeof(_WINTRUST_DATA), pPolicyCallbackData=None,
        pSIPClientData=None, dwUIChoice=WTD_UI_NONE,
        fdwRevocationChecks=WTD_REVOKE_NONE, dwUnionChoice=WTD_CHOICE_FILE,
        pFile=ctypes.pointer(file_info), dwStateAction=WTD_STATEACTION_VERIFY,
        hWVTStateData=None, pwszURLReference=None, dwProvFlags=0, dwUIContext=0)
    action_guid = _make_guid()

    try:
        result = wintrust.WinVerifyTrust(
            wintypes.HWND(-1), ctypes.byref(action_guid), ctypes.byref(data))
    except Exception:  # noqa: BLE001
        return "unknown"
    finally:
        data.dwStateAction = WTD_STATEACTION_CLOSE
        try:
            wintrust.WinVerifyTrust(
                wintypes.HWND(-1), ctypes.byref(action_guid), ctypes.byref(data))
        except Exception:  # noqa: BLE001
            pass

    if result == 0:
        return "signed"
    if result == _TRUST_E_NOSIGNATURE:
        return "unsigned"
    return "untrusted"


def _publisher(path: str) -> str:
    if not _VERSIONINFO_OK:
        return ""
    try:
        translations = win32api.GetFileVersionInfo(path, r"\VarFileInfo\Translation")
        lang, codepage = translations[0]
        key = f"\\StringFileInfo\\{lang:04x}{codepage:04x}\\CompanyName"
        return win32api.GetFileVersionInfo(path, key) or ""
    except Exception:  # noqa: BLE001
        return ""


def check(path: str) -> SignatureInfo:
    """Публичная точка входа для core.signature_worker.SignatureWorker."""
    if not path or path.startswith("<"):
        return SignatureInfo(status="unknown", signer="", checked=False)
    status = _verify_trust(path)
    signer = _publisher(path) if status != "unknown" else ""
    return SignatureInfo(status=status, signer=signer, checked=True)
