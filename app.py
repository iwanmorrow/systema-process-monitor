"""SYSTEMA Processes — GUI (tkinter/ttk).

Запуск:  python app.py
Язык по умолчанию — из локали ОС (i18n.detect_system_language), меняется в тулбаре.

GUI — тонкий слой поверх core.monitor.ProcessMonitor. Вся логика идентификации
процессов, event/polling-мерж, эвристики, хэширование и история живут в core/;
здесь только отрисовка и реакция на выбор пользователя.
"""

from __future__ import annotations

import csv
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Callable, Dict, List, Optional

import i18n
import theme as th
from core import monitor as mon
from core import network as netmod
from core.models import Severity
from presentation import (SEV_KEYS, SEV_TAGS, SIG_KEYS, event_row,  # noqa: F401
                          render_kind, render_reason)

APP_NAME = "SYSTEMA Processes"
VERSION = "2.0"
DB_PATH = "systema_history.sqlite3"

# (column id, ключ перевода, ширина, выравнивание)
PROC_COLUMNS = [
    ("pid", "col_pid", 70, "e"),
    ("ppid", "col_ppid", 70, "e"),
    ("sev", "col_sev", 80, "center"),
    ("name", "col_name", 190, "w"),
    ("user", "col_user", 140, "w"),
    ("cpu", "col_cpu", 65, "e"),
    ("rss", "col_rss", 85, "e"),
    ("thr", "col_thr", 70, "e"),
    ("started", "col_started", 155, "w"),
    ("exe", "col_exe", 300, "w"),
    ("cmd", "col_cmd", 460, "w"),
]

EVENT_COLUMNS = [
    ("time", "col_time", 80, "w"),
    ("kind", "col_kind", 70, "w"),
    ("source", "col_source", 78, "w"),
    ("sev", "col_sev", 80, "center"),
    ("pid", "col_pid", 65, "e"),
    ("name", "col_name", 160, "w"),
    ("user", "col_user", 120, "w"),
    ("chain", "col_chain", 380, "w"),
    ("flags", "d_reasons", 420, "w"),
]

NET_COLUMNS = [
    ("proto", "col_proto", 60, "w"),
    ("laddr", "col_laddr", 170, "w"),
    ("raddr", "col_raddr", 170, "w"),
    ("status", "col_status", 110, "w"),
]

def build_event_backend():
    """Windows -> WMI process trace; иначе None (core сам падает на polling)."""
    if sys.platform != "win32":
        return None
    try:
        from windows.wmi_events import WmiProcessEventBackend
    except ImportError:
        return None
    return WmiProcessEventBackend()


def build_signature_checker() -> Optional[Callable]:
    if sys.platform != "win32":
        return None
    try:
        from windows.signature import check
    except ImportError:
        return None
    return check


class KeyCombo(ttk.Frame):
    """Combobox, который хранит ключ, а показывает перевод."""

    def __init__(self, parent, label_key: str, keys: List[str], initial: str,
                 on_change: Callable[[str], None], width: int = 10,
                 labels: Optional[Dict[str, str]] = None):
        super().__init__(parent)
        self.label_key = label_key
        self.keys = keys
        self.labels = labels
        self.on_change = on_change
        self._key = initial
        self.label = ttk.Label(self, text=i18n.t(label_key))
        self.label.pack(side="left")
        self.var = tk.StringVar(value=self._text(initial))
        self.box = ttk.Combobox(self, textvariable=self.var, state="readonly",
                                width=width, values=[self._text(k) for k in keys],
                                takefocus=False)
        self.box.pack(side="left", padx=(6, 0))
        self.box.bind("<<ComboboxSelected>>", self._on_select)
        self.box.bind("<FocusIn>", lambda _e: self._deselect())

    def _text(self, key: str) -> str:
        return self.labels[key] if self.labels else i18n.t(key)

    def key(self) -> str:
        return self._key

    def _deselect(self) -> None:
        try:
            self.box.selection_clear()
        except Exception:  # noqa: BLE001
            pass
        self.after_idle(lambda: self.winfo_toplevel().focus_set())

    def _on_select(self, _event=None) -> None:
        idx = self.box.current()
        if 0 <= idx < len(self.keys):
            self._key = self.keys[idx]
            self.on_change(self._key)
        self._deselect()

    def retranslate(self) -> None:
        self.label.configure(text=i18n.t(self.label_key))
        self.box.configure(values=[self._text(k) for k in self.keys])
        self.var.set(self._text(self._key))


class Worker(threading.Thread):
    """Фоновый опрос, чтобы UI не подвисал. Контракт с core не меняется:
    poll() -> (snapshot, new_events), system_stats() -> dict."""

    def __init__(self, m: "mon.ProcessMonitor", out: queue.Queue):
        super().__init__(daemon=True)
        self.m = m
        self.out = out
        self.interval = 1.0
        self.paused = threading.Event()
        self.stopped = threading.Event()

    def run(self) -> None:
        while not self.stopped.is_set():
            if not self.paused.is_set():
                try:
                    snap, events = self.m.poll()
                    self.out.put((snap, events, self.m.system_stats()))
                except Exception as exc:  # noqa: BLE001
                    self.out.put(("error", str(exc), {}))
            self.stopped.wait(self.interval)


class App(tk.Tk):
    EVENT_ROW_CAP = 3000   # видимых строк в дереве истории; полная история — в SQLite

    def __init__(self) -> None:
        super().__init__()
        i18n.set_language(i18n.detect_system_language())

        self.title(f"{APP_NAME} {VERSION}")
        self.geometry("1440x820")
        self.minsize(1020, 600)

        self.monitor = mon.ProcessMonitor(
            db_path=DB_PATH,
            event_backend=build_event_backend(),
            signature_checker=build_signature_checker())
        self.queue: queue.Queue = queue.Queue()
        self.worker = Worker(self.monitor, self.queue)

        self.style = ttk.Style(self)
        self.current_palette = "light"
        self.colors: dict = {}

        self.filter_text = tk.StringVar()
        self.only_flagged = tk.BooleanVar(value=False)
        self.paused = tk.BooleanVar(value=False)
        self.interval = tk.DoubleVar(value=1.0)

        self.sort_col = "cpu"
        self.sort_rev = True
        self.procs: Dict[int, "mon.ProcInfo"] = {}
        self.selected_pid: Optional[int] = None
        self.last_stats: dict = {}
        self._first_render = True

        self._build_ui()
        self._apply_theme(force=True)

        self.filter_text.trace_add("write", lambda *_: self._render_procs())
        self.only_flagged.trace_add("write", lambda *_: self._render_procs())
        self.interval.trace_add("write", self._on_interval)

        self._bind_hotkeys()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.worker.start()
        self.after(150, self._drain)
        self.after(5000, self._theme_watch)

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        bar = ttk.Frame(self, padding=(8, 6))
        bar.pack(fill="x")

        self.btn_kill = ttk.Button(bar, text=i18n.t("kill"), command=self._kill_selected,
                                   takefocus=False)
        self.btn_kill.pack(side="right")
        self.btn_export = ttk.Button(bar, text=i18n.t("export"),
                                     command=self._export_events, takefocus=False)
        self.btn_export.pack(side="right", padx=(0, 8))

        self.lbl_filter = ttk.Label(bar, text=i18n.t("filter"))
        self.lbl_filter.pack(side="left")
        self.entry = ttk.Entry(bar, textvariable=self.filter_text, width=24)
        self.entry.pack(side="left", padx=(6, 14))

        self.view_combo = KeyCombo(bar, "view", ["view_tree", "view_list"],
                                   "view_tree", lambda _k: self._render_procs(), 9)
        self.view_combo.pack(side="left", padx=(0, 14))

        self.chk_flagged = ttk.Checkbutton(bar, text=i18n.t("only_flagged"),
                                           variable=self.only_flagged, takefocus=False)
        self.chk_flagged.pack(side="left", padx=(0, 14))

        self.lbl_interval = ttk.Label(bar, text=i18n.t("interval"))
        self.lbl_interval.pack(side="left")
        ttk.Spinbox(bar, from_=0.5, to=10.0, increment=0.5, width=5,
                    textvariable=self.interval, takefocus=False
                    ).pack(side="left", padx=(6, 14))

        self.chk_pause = ttk.Checkbutton(bar, text=i18n.t("pause"),
                                         variable=self.paused, command=self._on_pause,
                                         takefocus=False)
        self.chk_pause.pack(side="left", padx=(0, 14))

        self.theme_combo = KeyCombo(bar, "theme",
                                    ["theme_auto", "theme_dark", "theme_light"],
                                    "theme_auto",
                                    lambda _k: self._apply_theme(force=True), 8)
        self.theme_combo.pack(side="left", padx=(0, 14))

        self.lang_combo = KeyCombo(bar, "language", i18n.LANG_ORDER, i18n.current(),
                                   self._on_language, 9, labels=i18n.LANG_LABELS)
        self.lang_combo.pack(side="left")

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=8, pady=(0, 6))

        proc_tab = ttk.Frame(self.nb)
        self.nb.add(proc_tab, text=i18n.t("tab_procs"))
        paned = ttk.Panedwindow(proc_tab, orient="vertical")
        paned.pack(fill="both", expand=True)

        top = ttk.Frame(paned)
        self.tree = self._make_tree(top, PROC_COLUMNS, tree_column=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        paned.add(top, weight=4)

        bottom = ttk.Frame(paned)
        self._build_detail_panel(bottom)
        paned.add(bottom, weight=2)
        self.after(200, lambda: paned.sashpos(0, int(self.winfo_height() * 0.6)))

        ev_tab = ttk.Frame(self.nb)
        self.nb.add(ev_tab, text=i18n.t("tab_events"))
        self.ev_tree = self._make_tree(ev_tab, EVENT_COLUMNS, tree_column=False)

        self.status = ttk.Label(self, text=i18n.t("starting"), style="Status.TLabel",
                                anchor="w")
        self.status.pack(fill="x", side="bottom")
        self._render_details(None)

    def _build_detail_panel(self, parent) -> None:
        """Панель анализа выбранного процесса: Обзор / Безопасность / Связи / Сеть."""
        self.detail_nb = ttk.Notebook(parent)
        self.detail_nb.pack(fill="both", expand=True)

        self.tab_overview = tk.Text(self.detail_nb, wrap="word", relief="flat",
                                    font=(th.MONO, 9), padx=10, pady=8,
                                    borderwidth=0, highlightthickness=0, cursor="xterm")
        self.tab_overview.configure(state="disabled")
        # Текст остаётся нередактируемым (state=disabled), но выделение и
        # копирование мышью/Ctrl+C уже поддержаны самим Tk даже в disabled-
        # состоянии — курсор "xterm" (I-beam) просто делает это заметным, а
        # явный биндинг ниже — подстраховка на случай платформенных отличий
        # (в частности, есть сообщения о том, что реальные Windows-сборки Tk
        # не всегда надёжно доставляют встроенный <<Copy>> для disabled Text).
        self.tab_overview.bind("<Control-c>", self._copy_overview_selection)
        self.detail_nb.add(self.tab_overview, text=i18n.t("tab_overview"))

        self.tab_security = tk.Text(self.detail_nb, wrap="word", relief="flat",
                                    font=(th.MONO, 9), padx=10, pady=8,
                                    borderwidth=0, highlightthickness=0, cursor="arrow")
        self.tab_security.configure(state="disabled")
        self.detail_nb.add(self.tab_security, text=i18n.t("tab_security"))

        self.tab_relations = tk.Text(self.detail_nb, wrap="word", relief="flat",
                                     font=(th.MONO, 9), padx=10, pady=8,
                                     borderwidth=0, highlightthickness=0, cursor="arrow")
        self.tab_relations.configure(state="disabled")
        self.detail_nb.add(self.tab_relations, text=i18n.t("tab_relationships"))

        net_frame = ttk.Frame(self.detail_nb)
        net_bar = ttk.Frame(net_frame, padding=(4, 4))
        net_bar.pack(fill="x")
        self.btn_net_refresh = ttk.Button(net_bar, text=i18n.t("net_refresh"),
                                          command=self._refresh_network, takefocus=False)
        self.btn_net_refresh.pack(side="left")
        self.lbl_net_hint = ttk.Label(net_bar, text=i18n.t("net_hint"), style="Muted.TLabel")
        self.lbl_net_hint.pack(side="left", padx=(10, 0))
        self.net_tree = self._make_tree(net_frame, NET_COLUMNS, tree_column=False)
        self.detail_nb.add(net_frame, text=i18n.t("tab_network"))

        self._detail_texts = [self.tab_overview, self.tab_security, self.tab_relations]

    def _bind_hotkeys(self) -> None:
        self.bind("<Control-f>", lambda _e: (self.entry.focus_set(),
                                             self.entry.select_range(0, "end")))
        self.bind("<Control-e>", lambda _e: self._export_events())
        self.bind("<Delete>", lambda _e: self._kill_selected())
        self.bind("<space>", lambda _e: (self.paused.set(not self.paused.get()),
                                         self._on_pause()))
        self.bind("<Escape>", lambda _e: (self.filter_text.set(""),
                                          self.focus_set()))

    def _make_tree(self, parent, columns, tree_column: bool) -> ttk.Treeview:
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        ids = [c[0] for c in columns]
        tree = ttk.Treeview(frame, columns=ids,
                            show="tree headings" if tree_column else "headings",
                            selectmode="browse", takefocus=False)
        if tree_column:
            tree.column("#0", width=30, stretch=False)
            tree.heading("#0", text="")
        else:
            tree.column("#0", width=0, stretch=False)
        for cid, key, width, anchor in columns:
            tree.heading(cid, text=i18n.t(key),
                         command=lambda c=cid, t=tree: self._sort_by(c, t))
            tree.column(cid, width=width, anchor=anchor, stretch=False)
        vs = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        hs = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        return tree

    # ------------------------------------------------------------ язык

    def _on_language(self, code: str) -> None:
        i18n.set_language(code)
        self._retranslate()

    def _retranslate(self) -> None:
        self.lbl_filter.configure(text=i18n.t("filter"))
        self.lbl_interval.configure(text=i18n.t("interval"))
        self.chk_flagged.configure(text=i18n.t("only_flagged"))
        self.chk_pause.configure(text=i18n.t("pause"))
        self.btn_kill.configure(text=i18n.t("kill"))
        self.btn_export.configure(text=i18n.t("export"))
        for combo in (self.view_combo, self.theme_combo, self.lang_combo):
            combo.retranslate()
        self.nb.tab(0, text=i18n.t("tab_procs"))
        self.nb.tab(1, text=i18n.t("tab_events"))
        for tree, columns in ((self.tree, PROC_COLUMNS), (self.ev_tree, EVENT_COLUMNS),
                              (self.net_tree, NET_COLUMNS)):
            for cid, key, _w, _a in columns:
                tree.heading(cid, text=i18n.t(key))
        for idx, key in enumerate(("tab_overview", "tab_security", "tab_relationships",
                                   "tab_network")):
            self.detail_nb.tab(idx, text=i18n.t(key))
        self.btn_net_refresh.configure(text=i18n.t("net_refresh"))
        self.lbl_net_hint.configure(text=i18n.t("net_hint"))
        self._render_details(self.procs.get(self.selected_pid))
        self._render_status()
        # Дерево процессов само перерисовывает каждую строку на следующем
        # тике опроса — но без явного вызова здесь один тик после смены языка
        # показывал бы старые подписи (severity и т.п.). История событий сама
        # НЕ обновляется каждый тик (только дописывается), поэтому для неё
        # полная перерисовка — не подстраховка, а единственный способ не
        # оставить строки на предыдущем языке навсегда.
        self._render_procs()
        self._rebuild_event_tree()

    # --------------------------------------------------------------- темы

    def _resolve_theme(self) -> str:
        key = self.theme_combo.key()
        if key == "theme_dark":
            return "dark"
        if key == "theme_light":
            return "light"
        return th.detect_system_theme()

    def _apply_theme(self, force: bool = False) -> None:
        target = self._resolve_theme()
        if not force and target == self.current_palette:
            return
        self.current_palette = target
        c = th.apply(self, self.style, target)
        self.colors = c
        th.apply_titlebar(self, target, c)
        for tree in (self.tree, self.ev_tree, self.net_tree):
            tree.tag_configure("flagged", foreground=c["warn"], background=c["warnbg"])
            tree.tag_configure("sev_low", foreground=c["sev_low"], background=c["sev_low_bg"])
            tree.tag_configure("sev_medium", foreground=c["sev_medium"],
                               background=c["sev_medium_bg"])
            tree.tag_configure("sev_high", foreground=c["sev_high"], background=c["sev_high_bg"])
            tree.tag_configure("start", foreground=c["ok"], background=c["field"])
            tree.tag_configure("exit", foreground=c["muted"], background=c["field"])
            tree.tag_configure("even", background=c["field"])
            tree.tag_configure("odd", background=c["stripe"])
        for text in self._detail_texts:
            text.configure(bg=c["field"], fg=c["fg"], insertbackground=c["fg"],
                           selectbackground=c["sel"], selectforeground=c["selfg"])
            text.tag_configure("h", foreground=c["accent"], font=(th.UI_FONT, 10, "bold"))
            text.tag_configure("sev_low", foreground=c["sev_low"])
            text.tag_configure("sev_medium", foreground=c["sev_medium"])
            text.tag_configure("sev_high", foreground=c["sev_high"])
            text.tag_configure("muted", foreground=c["muted"])

    def _theme_watch(self) -> None:
        if self.theme_combo.key() == "theme_auto":
            self._apply_theme(force=False)
        self.after(5000, self._theme_watch)

    # ------------------------------------------------------------ события

    def _on_pause(self) -> None:
        if self.paused.get():
            self.worker.paused.set()
        else:
            self.worker.paused.clear()

    def _on_interval(self, *_args) -> None:
        try:
            self.worker.interval = max(0.5, float(self.interval.get()))
        except (tk.TclError, ValueError):
            pass

    def _sort_by(self, col: str, tree: ttk.Treeview) -> None:
        if tree is not self.tree:
            return
        if self.sort_col == col:
            self.sort_rev = not self.sort_rev
        else:
            self.sort_col, self.sort_rev = col, col in ("cpu", "rss", "started", "sev")
        self._render_procs()

    def _on_select(self, _event=None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        try:
            pid = int(sel[0])
        except ValueError:
            return
        self.selected_pid = pid
        self._render_details(self.procs.get(pid))
        self.net_tree.delete(*self.net_tree.get_children(""))

    def _kill_selected(self) -> None:
        if self.selected_pid is None:
            return
        info = self.procs.get(self.selected_pid)
        name = info.name if info else "?"
        if not messagebox.askyesno(
                i18n.t("confirm_title"),
                i18n.t("confirm_kill", name=name, pid=self.selected_pid)):
            return
        err = self.monitor.kill(self.selected_pid)
        if err:
            message = i18n.t(err)
            if err == "err_failed" and self.monitor.last_error_detail:
                message += f": {self.monitor.last_error_detail}"   # сырой текст ОС
            messagebox.showerror(i18n.t("error_title"), message)

    def _refresh_network(self) -> None:
        if self.selected_pid is None:
            return
        pid = self.selected_pid
        conns = netmod.connections_for(pid)
        self.net_tree.delete(*self.net_tree.get_children(""))
        if not conns:
            self.net_tree.insert("", "end", values=(i18n.t("net_empty"), "", "", ""))
            return
        for c in conns:
            laddr = f"{c.laddr}:{c.lport}" if c.laddr else ""
            raddr = f"{c.raddr}:{c.rport}" if c.raddr else ""
            self.net_tree.insert("", "end", values=(c.proto, laddr, raddr, c.status))

    def _export_events(self) -> None:
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")],
            initialfile=time.strftime("systema-events-%Y%m%d-%H%M%S.csv"))
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.writer(fh, delimiter=";")
            w.writerow(["timestamp", "kind", "source", "severity", "pid", "ppid",
                        "name", "user", "sha256", "reasons", "chain", "cmdline"])
            for e in self.monitor.events:
                # kind/severity намеренно НЕ переводятся — CSV машинно-читаемый,
                # схема не должна плыть при смене языка. "reasons" — единственное
                # поле с текстом для человека, рендерится на текущем языке через
                # тот же render_reason(), что и вкладка "Безопасность / Файл".
                reasons_text = "; ".join(render_reason(c, p) for c, p in e.reasons)
                w.writerow([time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e.ts)),
                            e.kind, e.source, e.severity.value, e.pid, e.ppid,
                            e.name, e.username, e.sha256 or "", reasons_text,
                            e.parent_chain, e.cmdline])

    def _on_close(self) -> None:
        # Порядок важен. Сначала останавливаем и ДОЖИДАЕМСЯ поток опроса:
        # poll() может быть в самом разгаре и вот-вот вызвать history.add().
        # Если закрыть историю раньше, такое событие попадёт в очередь уже
        # после сигнала остановки SQLite-писателя и будет потеряно молча.
        self.worker.stopped.set()
        if self.worker.is_alive():
            self.worker.join(timeout=3.0)
        self.monitor.shutdown()
        self.destroy()

    # ---------------------------------------------------------- рендеринг

    def _drain(self) -> None:
        payload = None
        while True:
            try:
                payload = self.queue.get_nowait()
            except queue.Empty:
                break
        if payload:
            snap, events, stats = payload
            if snap == "error":
                self.status.configure(text=i18n.t("poll_error", err=events))
            else:
                self.procs = snap
                self.last_stats = stats
                self._render_procs()
                if events:
                    self._append_events(events)
                self._render_status()
        self.after(300, self._drain)

    def _render_status(self) -> None:
        if not self.last_stats:
            return
        sys_line = i18n.t("sys_line", **{k: self.last_stats[k]
                                         for k in ("cpu", "ram", "used", "total")})
        status_key = {"disabled": "backend_disabled", "active": "backend_active",
                     "unavailable": "backend_unavailable"}.get(
                         self.monitor.event_backend_status, "backend_disabled")
        backend_text = i18n.t(status_key)
        code = getattr(self.monitor, "event_backend_error", "")
        if code:
            backend_text += f" — {i18n.t('backend_err_' + code)}"
        detail = getattr(self.monitor, "event_backend_detail", "")
        if detail:
            backend_text += f" ({detail})"   # сырой текст ОС, не переводится
        self.status.configure(text=i18n.t(
            "status", sys=sys_line, procs=len(self.procs),
            events=len(self.monitor.events), time=time.strftime("%H:%M:%S"))
            + f"   |   {i18n.t('backend_label')} {backend_text}")

    def _matches(self, p: "mon.ProcInfo", needle: str) -> bool:
        if self.only_flagged.get() and not p.flags:
            return False
        if not needle:
            return True
        return (needle in p.name.lower() or needle in p.exe.lower()
                or needle in p.cmdline.lower() or needle in p.username.lower()
                or needle == str(p.pid))

    def _row_tag(self, p: "mon.ProcInfo", row: int) -> str:
        sev = p.severity
        if sev in SEV_TAGS:
            return SEV_TAGS[sev]
        return "odd" if row % 2 else "even"

    def _row(self, p: "mon.ProcInfo") -> tuple:
        return (p.pid, p.ppid, i18n.t(SEV_KEYS[p.severity]), p.name, p.username,
                f"{p.cpu:.1f}", f"{p.rss_mb:.1f}", p.threads, p.started, p.exe, p.cmdline)

    def _sort_key(self, p: "mon.ProcInfo"):
        return {
            "pid": p.pid, "ppid": p.ppid, "sev": p.severity.rank, "name": p.name.lower(),
            "user": p.username.lower(), "cpu": p.cpu, "rss": p.rss,
            "thr": p.threads, "started": p.create_time,
            "exe": p.exe.lower(), "cmd": p.cmdline.lower(),
        }.get(self.sort_col, p.pid)

    def _render_procs(self) -> None:
        tree = self.tree
        needle = self.filter_text.get().strip().lower()
        procs = self.procs
        if not procs:
            return

        open_pids = {iid for iid in self._all_items(tree) if tree.item(iid, "open")}
        yview = tree.yview()[0]

        visible = {pid for pid, p in procs.items() if self._matches(p, needle)}
        tree_mode = self.view_combo.key() == "view_tree"

        if tree_mode and (needle or self.only_flagged.get()):
            for pid in list(visible):
                cur = procs.get(pid)
                depth = 0
                while cur and cur.ppid in procs and depth < 16:
                    visible.add(cur.ppid)
                    cur = procs[cur.ppid]
                    depth += 1

        tree.delete(*tree.get_children(""))

        if tree_mode:
            children: Dict[int, List["mon.ProcInfo"]] = {}
            roots: List["mon.ProcInfo"] = []
            for pid in visible:
                p = procs[pid]
                if p.ppid in visible and p.ppid != p.pid:
                    children.setdefault(p.ppid, []).append(p)
                else:
                    roots.append(p)
            for k in children:
                children[k].sort(key=self._sort_key, reverse=self.sort_rev)
            roots.sort(key=self._sort_key, reverse=self.sort_rev)

            stack = [(p, "") for p in reversed(roots)]
            row = 0
            while stack:
                p, parent = stack.pop()
                iid = tree.insert(parent, "end", iid=str(p.pid), text="",
                                  values=self._row(p), tags=(self._row_tag(p, row),))
                row += 1
                if self._first_render or needle or str(p.pid) in open_pids:
                    tree.item(iid, open=True)
                for ch in reversed(children.get(p.pid, [])):
                    stack.append((ch, iid))
        else:
            rows = sorted((procs[pid] for pid in visible),
                          key=self._sort_key, reverse=self.sort_rev)
            for row, p in enumerate(rows):
                tree.insert("", "end", iid=str(p.pid), text="", values=self._row(p),
                            tags=(self._row_tag(p, row),))

        self._first_render = False
        if self.selected_pid is not None and tree.exists(str(self.selected_pid)):
            tree.selection_set(str(self.selected_pid))
            self._render_details(procs.get(self.selected_pid))
        tree.yview_moveto(yview)

    def _all_items(self, tree: ttk.Treeview, parent: str = "") -> List[str]:
        out: List[str] = []
        for iid in tree.get_children(parent):
            out.append(iid)
            out.extend(self._all_items(tree, iid))
        return out

    def _append_events(self, events: List["mon.Event"]) -> None:
        tree = self.ev_tree
        at_top = tree.yview()[0] <= 0.01
        for e in events:
            values, tag = event_row(e)
            tree.insert("", 0, values=values, tags=(tag,))
        kids = tree.get_children("")
        if len(kids) > self.EVENT_ROW_CAP:
            tree.delete(*kids[self.EVENT_ROW_CAP:])
        if at_top:
            tree.yview_moveto(0)

    def _rebuild_event_tree(self) -> None:
        """Перерисовать всю вкладку «История событий» на текущем языке.

        Строки истории рендерятся на язык ОДИН РАЗ, в момент вставки — иначе
        при переключении RU/EN старые строки так и остались бы на прежнем
        языке навсегда (реальный баг, а не гипотетический: дерево не хранит
        сам HistoryEvent, только уже отформатированный текст). Источник
        истины при перерисовке — self.monitor.events (тот же bounded deque,
        что и всегда), а не то, что уже было в дереве, так что перерисовка
        не может «законсервировать» устаревший перевод."""
        tree = self.ev_tree
        yview = tree.yview()[0]
        tree.delete(*tree.get_children(""))
        recent = list(self.monitor.events)[-self.EVENT_ROW_CAP:]
        for e in recent:
            values, tag = event_row(e)
            tree.insert("", 0, values=values, tags=(tag,))
        tree.yview_moveto(yview)

    # ------------------------------------------------------ панель анализа

    def _copy_overview_selection(self, _event=None) -> str:
        """Явное Ctrl+C для вкладки «Обзор» — путь, cmdline, PID и т.п. часто
        нужно скопировать целиком. Копирует текущее выделение, если оно есть;
        если выделения нет — ничего не делает (не бросает исключение)."""
        try:
            selected = self.tab_overview.get("sel.first", "sel.last")
        except tk.TclError:
            return "break"
        self.tab_overview.clipboard_clear()
        self.tab_overview.clipboard_append(selected)
        return "break"

    def _set_text(self, widget: tk.Text, segments: List[tuple]) -> None:
        """segments: список (текст, tag|None). Каждый элемент — один "абзац"."""
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        for text, tag in segments:
            if tag:
                widget.insert("end", text + "\n", tag)
            else:
                widget.insert("end", text + "\n")
        widget.configure(state="disabled")

    def _render_details(self, p: Optional["mon.ProcInfo"]) -> None:
        if p is None:
            for w in self._detail_texts:
                self._set_text(w, [(i18n.t("no_selection"), None)])
            return
        self._render_overview(p)
        self._render_security(p)
        self._render_relationships(p)

    def _render_overview(self, p: "mon.ProcInfo") -> None:
        parent = self.procs.get(p.ppid)
        rows = [
            (f"{p.name}   PID {p.pid}   PPID {p.ppid}"
             + (f" ({parent.name})" if parent else ""), "h"),
            (f"{i18n.t('d_user')}       : {p.username}", None),
            (f"{i18n.t('d_status')}     : {p.status}   {i18n.t('d_threads')}: {p.threads}"
             + (f"   {i18n.t('d_handles')}: {p.handles}" if p.handles >= 0 else ""), None),
            (f"{i18n.t('d_started')}    : {p.started}", None),
            (f"{i18n.t('d_cpu_ram')}    : {p.cpu:.1f} %   /   {p.rss_mb:.1f} MB", None),
            (f"{i18n.t('d_image')}      : {p.exe}", None),
            (f"{i18n.t('d_cmd')}        : {p.cmdline}", None),
        ]
        self._set_text(self.tab_overview, rows)

    def _render_security(self, p: "mon.ProcInfo") -> None:
        rows: List[tuple] = [(f"{p.name}   PID {p.pid}", "h")]

        if p.sha256 is None:
            hash_line = i18n.t("d_hash_pending")
        else:
            hash_line = p.sha256
        rows.append((f"{i18n.t('d_hash')}      : {hash_line}", None))

        sig = p.signature
        if sig.checked:
            sig_line = i18n.t(SIG_KEYS.get(sig.status, "sig_unknown"))
        else:
            sig_line = i18n.t("sig_unknown")
        rows.append((f"{i18n.t('d_signature')}     : {sig_line}", None))
        publisher = sig.signer or i18n.t("d_publisher_none")
        rows.append((f"{i18n.t('d_publisher')} : {publisher}", "muted"))

        sev = p.severity
        sev_tag = SEV_TAGS.get(sev)
        rows.append((f"{i18n.t('d_severity')}   : {i18n.t(SEV_KEYS[sev])}", sev_tag or "h"))
        if p.hits:
            for h in p.hits:
                rows.append((f"  • [{h.severity.value}] {render_reason(h.code, h.params)}",
                            SEV_TAGS.get(h.severity)))
            rows.append((f"  {i18n.t('d_severity_note')}", "muted"))
        else:
            rows.append((f"  {i18n.t('d_no_reasons')}", "muted"))

        self._set_text(self.tab_security, rows)

    def _render_relationships(self, p: "mon.ProcInfo") -> None:
        parent = self.procs.get(p.ppid)
        rows: List[tuple] = [(f"{p.name}   PID {p.pid}", "h")]
        parent_line = f"{parent.name} (PID {parent.pid})" if parent else i18n.t("d_parent_none")
        rows.append((f"{i18n.t('d_parent')}     : {parent_line}", None))
        rows.append((f"{i18n.t('d_chain_full')} : {self.monitor.chain(p.pid)}", None))

        children = sorted(self.monitor.children(p.pid), key=lambda c: c.name.lower())
        rows.append(("", None))
        rows.append((f"{i18n.t('d_children')} ({len(children)}):", "h"))
        if children:
            for ch in children:
                rows.append((f"  • {ch.name} (PID {ch.pid}, {ch.username})", None))
        else:
            rows.append((f"  {i18n.t('d_children_none')}", "muted"))

        self._set_text(self.tab_relations, rows)


def main() -> None:
    App().mainloop()


if __name__ == "__main__":
    main()
