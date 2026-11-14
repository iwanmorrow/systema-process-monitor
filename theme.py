"""Systema Process Monitor — темы оформления.

Определяет системную тему (Windows / macOS / Linux), применяет палитру к ttk
и перекрашивает системный заголовок окна (Windows 10 1809+ / Windows 11).
"""

from __future__ import annotations

import subprocess
import sys
from tkinter import ttk

PALETTES = {
    "dark": {
        "bg": "#1e1f22", "panel": "#26282c", "field": "#181a1d",
        "fg": "#e3e5e8", "muted": "#9aa0a6", "border": "#3a3d42",
        "sel": "#2f5fbf", "selfg": "#ffffff", "alt": "#212327",
        "stripe": "#212428", "hover": "#2c2f34",
        "accent": "#4f8cff", "warn": "#ff6b61", "ok": "#4cc38a",
        "warnbg": "#3a2220",
        "sev_low": "#d8c85a", "sev_low_bg": "#332f1c",
        "sev_medium": "#e8a33d", "sev_medium_bg": "#3a2c18",
        "sev_high": "#ff6b61", "sev_high_bg": "#3a2220",
    },
    "light": {
        "bg": "#f3f4f6", "panel": "#ffffff", "field": "#ffffff",
        "fg": "#1c1e21", "muted": "#5f6368", "border": "#c9ccd1",
        "sel": "#cfe0ff", "selfg": "#0b2a5b", "alt": "#eceef1",
        "stripe": "#eef0f3", "hover": "#e6e8ec",
        "accent": "#1a73e8", "warn": "#c5221f", "ok": "#188038",
        "warnbg": "#fdecea",
        "sev_low": "#8a6d00", "sev_low_bg": "#fbf3d9",
        "sev_medium": "#b35c00", "sev_medium_bg": "#fdead1",
        "sev_high": "#c5221f", "sev_high_bg": "#fdecea",
    },
}

MONO = ("Consolas" if sys.platform == "win32" else "Menlo" if sys.platform == "darwin"
        else "DejaVu Sans Mono")
UI_FONT = ("Segoe UI" if sys.platform == "win32" else "Helvetica" if sys.platform == "darwin"
           else "DejaVu Sans")


# --------------------------------------------------------------- детекция

def detect_system_theme() -> str:
    """Вернуть 'dark' или 'light' по настройкам ОС."""
    try:
        if sys.platform == "win32":
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
            value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
            winreg.CloseKey(key)
            return "light" if value else "dark"
        if sys.platform == "darwin":
            out = subprocess.run(["defaults", "read", "-g", "AppleInterfaceStyle"],
                                 capture_output=True, text=True, timeout=2)
            return "dark" if "Dark" in out.stdout else "light"
        out = subprocess.run(
            ["gsettings", "get", "org.gnome.desktop.interface", "color-scheme"],
            capture_output=True, text=True, timeout=2)
        if "dark" in out.stdout.lower():
            return "dark"
        out = subprocess.run(
            ["gsettings", "get", "org.gnome.desktop.interface", "gtk-theme"],
            capture_output=True, text=True, timeout=2)
        return "dark" if "dark" in out.stdout.lower() else "light"
    except Exception:  # noqa: BLE001
        return "light"


# ------------------------------------------------------ заголовок окна (Win)

def _colorref(hex_color: str) -> int:
    """#RRGGBB -> COLORREF (0x00BBGGRR)."""
    r = int(hex_color[1:3], 16)
    g = int(hex_color[3:5], 16)
    b = int(hex_color[5:7], 16)
    return (b << 16) | (g << 8) | r


def apply_titlebar(root, mode: str, c: dict) -> None:
    """Тёмный/светлый системный заголовок окна.

    DWMWA_USE_IMMERSIVE_DARK_MODE = 20 (19 на сборках Windows 10 < 19041),
    DWMWA_CAPTION_COLOR = 35 и DWMWA_TEXT_COLOR = 36 — только Windows 11.
    На других ОС и старых сборках вызовы молча игнорируются.
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes
        root.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        dwm = ctypes.windll.dwmapi

        flag = ctypes.c_int(1 if mode == "dark" else 0)
        for attr in (20, 19):
            if dwm.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(flag),
                                         ctypes.sizeof(flag)) == 0:
                break

        for attr, key in ((35, "panel"), (36, "fg"), (34, "border")):
            value = ctypes.c_int(_colorref(c[key]))
            dwm.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(value),
                                      ctypes.sizeof(value))

        # форсированная перерисовка рамки: сдвиг на пиксель и обратно
        geo = root.geometry()
        size, _, rest = geo.partition("+")
        w, _, h = size.partition("x")
        if w.isdigit() and h.isdigit():
            root.geometry(f"{int(w) + 1}x{h}+{rest}" if rest else f"{int(w) + 1}x{h}")
            root.update_idletasks()
            root.geometry(geo)
    except Exception:  # noqa: BLE001
        pass


# ------------------------------------------------------------------ стили

def apply(root, style: ttk.Style, mode: str) -> dict:
    """Применить палитру. mode: 'dark' | 'light'. Возвращает палитру."""
    c = PALETTES[mode]
    style.theme_use("clam")

    root.configure(bg=c["bg"])
    style.configure(".", background=c["bg"], foreground=c["fg"],
                    fieldbackground=c["field"], bordercolor=c["border"],
                    lightcolor=c["border"], darkcolor=c["border"],
                    troughcolor=c["bg"], focuscolor=c["bg"],
                    font=(UI_FONT, 9))

    style.configure("TFrame", background=c["bg"])
    style.configure("Panel.TFrame", background=c["panel"])
    style.configure("TLabel", background=c["bg"], foreground=c["fg"])
    style.configure("Muted.TLabel", background=c["bg"], foreground=c["muted"])
    style.configure("Status.TLabel", background=c["panel"], foreground=c["muted"],
                    font=(MONO, 9), padding=(8, 4))

    # --- кнопки: без пунктирной фокус-рамки, ровная заливка
    style.configure("TButton", background=c["panel"], foreground=c["fg"],
                    bordercolor=c["border"], focuscolor=c["panel"],
                    relief="flat", padding=(12, 5))
    style.map("TButton",
              background=[("pressed", c["border"]), ("active", c["hover"])],
              bordercolor=[("active", c["accent"])],
              foreground=[("disabled", c["muted"])])

    # --- чекбоксы: квадратик в цвет темы, галочка на акценте
    style.configure("TCheckbutton", background=c["bg"], foreground=c["fg"],
                    focuscolor=c["bg"], indicatorbackground=c["field"],
                    indicatorforeground=c["fg"], indicatorrelief="flat",
                    padding=(2, 2))
    style.map("TCheckbutton",
              background=[("active", c["bg"])],
              indicatorbackground=[("selected", c["accent"]),
                                   ("active", c["hover"])],
              indicatorforeground=[("selected", "#ffffff")])

    # --- поля ввода: выделение текста в цвет темы
    style.configure("TEntry", fieldbackground=c["field"], foreground=c["fg"],
                    insertcolor=c["fg"], bordercolor=c["border"],
                    selectbackground=c["sel"], selectforeground=c["selfg"],
                    relief="flat", padding=4)
    style.map("TEntry", bordercolor=[("focus", c["accent"])])

    style.configure("TSpinbox", fieldbackground=c["field"], foreground=c["fg"],
                    arrowcolor=c["fg"], bordercolor=c["border"],
                    selectbackground=c["sel"], selectforeground=c["selfg"],
                    focuscolor=c["field"], relief="flat", arrowsize=11, padding=3)
    style.map("TSpinbox", bordercolor=[("focus", c["accent"])])

    # --- комбобокс: readonly не должен выглядеть «выделенным текстом»
    style.configure("TCombobox", fieldbackground=c["field"], foreground=c["fg"],
                    background=c["panel"], arrowcolor=c["fg"],
                    bordercolor=c["border"], focuscolor=c["field"],
                    selectbackground=c["field"], selectforeground=c["fg"],
                    relief="flat", arrowsize=12, padding=3)
    style.map("TCombobox",
              fieldbackground=[("readonly", c["field"]), ("disabled", c["bg"])],
              foreground=[("readonly", c["fg"]), ("disabled", c["muted"])],
              selectbackground=[("readonly", c["field"]), ("focus", c["field"])],
              selectforeground=[("readonly", c["fg"]), ("focus", c["fg"])],
              background=[("readonly", c["panel"]), ("active", c["hover"])],
              bordercolor=[("hover", c["accent"]), ("focus", c["accent"])],
              arrowcolor=[("disabled", c["muted"])])
    # выпадающий список — это tk.Listbox, стилизуется только через option_add
    root.option_add("*TCombobox*Listbox.background", c["field"])
    root.option_add("*TCombobox*Listbox.foreground", c["fg"])
    root.option_add("*TCombobox*Listbox.selectBackground", c["accent"])
    root.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")
    root.option_add("*TCombobox*Listbox.borderWidth", 0)
    root.option_add("*TCombobox*Listbox.highlightThickness", 0)

    style.configure("TNotebook", background=c["bg"], bordercolor=c["border"],
                    tabmargins=(2, 4, 2, 0))
    style.configure("TNotebook.Tab", background=c["bg"], foreground=c["muted"],
                    padding=(16, 7), bordercolor=c["border"], focuscolor=c["panel"])
    style.map("TNotebook.Tab",
              background=[("selected", c["panel"]), ("active", c["hover"])],
              foreground=[("selected", c["fg"])],
              expand=[("selected", (0, 0, 0, 0))])

    style.configure("Treeview", background=c["field"], fieldbackground=c["field"],
                    foreground=c["fg"], bordercolor=c["border"], borderwidth=0,
                    rowheight=21, font=(MONO, 9))
    style.map("Treeview",
              background=[("selected", c["sel"])],
              foreground=[("selected", c["selfg"])])
    style.configure("Treeview.Heading", background=c["panel"], foreground=c["muted"],
                    font=(UI_FONT, 9, "bold"), padding=(8, 5), relief="flat",
                    bordercolor=c["border"])
    style.map("Treeview.Heading",
              background=[("active", c["hover"]), ("pressed", c["border"])],
              relief=[("active", "flat"), ("pressed", "flat")])
    # убрать пунктирный прямоугольник фокуса на строке
    try:
        style.layout("Treeview.Item", [
            ("Treeitem.padding", {"sticky": "nswe", "children": [
                ("Treeitem.indicator", {"side": "left", "sticky": ""}),
                ("Treeitem.image", {"side": "left", "sticky": ""}),
                ("Treeitem.text", {"side": "left", "sticky": ""}),
            ]}),
        ])
    except Exception:  # noqa: BLE001
        pass

    style.configure("TPanedwindow", background=c["bg"])
    style.configure("Sash", background=c["border"], sashthickness=5, gripcount=0,
                    bordercolor=c["bg"], lightcolor=c["border"], darkcolor=c["border"])

    for orient in ("Vertical", "Horizontal"):
        style.configure(f"{orient}.TScrollbar", background=c["border"],
                        troughcolor=c["bg"], arrowcolor=c["muted"],
                        bordercolor=c["bg"], relief="flat", arrowsize=12)
        style.map(f"{orient}.TScrollbar",
                  background=[("active", c["muted"]), ("pressed", c["accent"])])

    style.configure("TSeparator", background=c["border"])
    return c
