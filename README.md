# SYSTEMA Processes

A process-monitoring module within SYSTEMA (System Analysis & Monitoring Architecture).

SYSTEMA Processes is not a task manager. It is an observation tool: it shows what is happening, records what happened, connects processes into parent-child chains, and **explains why** something was flagged as suspicious instead of issuing a verdict.

This is a defensive monitoring tool. It is neither an antivirus product nor a full forensic suite.

**Requirements:** Python 3.10+, `tkinter`/`ttk`, and `psutil`. On Windows, `pywin32` is also required for the WMI event backend.

## Verification status — read this first

| Component | Status |
|---|---|
| `core/` (identity, polling, events, history, hashing, heuristics, workers), `presentation.py`, and i18n | **Verified with automated tests and runs on Linux** (62 tests) |
| GUI (tabs, language switching, Ctrl+C, shutdown) | Tested under Xvfb on Linux; not tested on Windows |
| `windows/wmi_events.py` (WMI process tracing) | **Not run on Windows.** Static review and non-Windows fallback behavior only |
| `windows/signature.py` (Authenticode) | **Not run on Windows.** Static review only |
| Dark window title bar (DWM) and `build.bat` packaging | **Not tested on Windows** |

This README does not claim that the application works on Windows: the development environment was not Windows. See **Windows verification checklist** for the tests that still need to be performed there.

## Architecture

```text
systema/
├── app.py                 GUI (tkinter/ttk): rendering and user interaction only
├── presentation.py        Converts (code, params) and core enums into localized text; no tkinter dependency
├── i18n.py                RU/EN strings and OS-language detection
├── theme.py               Dark/light palettes and the Windows DWM title bar
├── core/                  Platform-, GUI-, and i18n-independent logic
│   ├── identity.py        ProcessKey(pid, create_time): the single process-identity criterion
│   ├── models.py          ProcessInfo, HistoryEvent, HeuristicHit, Severity, ...
│   ├── backend.py         EventBackend interface
│   ├── polling_backend.py psutil snapshots and diffs; the sole source of CPU/RAM/thread/handle metrics
│   ├── heuristics.py      RuleEngine -> HeuristicHit(code, severity, params)
│   ├── hashing.py         Background SHA-256 hashing; cache keyed by (path, size, mtime)
│   ├── signature_worker.py Background signature verification (checker is injected)
│   ├── history.py         History: bounded deque and asynchronous SQLite writes
│   ├── network.py         On-demand process connections via psutil
│   └── monitor.py         ProcessMonitor orchestrator
├── windows/               Windows-specific modules, loaded lazily on win32 only
│   ├── wmi_events.py      WMI process trace (event-driven START/EXIT)
│   └── signature.py       Authenticode verification via WinVerifyTrust
├── tests/                 pytest suite (62 tests)
├── requirements.txt       Runtime dependencies: psutil (+ pywin32 on Windows)
├── requirements-dev.txt   Development dependencies: pytest, pyinstaller
└── build.bat              PyInstaller executable build script
```

The import graph is acyclic and has a single direction: `app -> presentation -> core`, `windows -> core`, while `core` imports nothing from the other layers. This is verified: `core/*` can be imported while `tkinter`, `pywin32`, `i18n`, `theme`, and `app` are blocked. The old flat `monitor.py` has been removed, and nothing references it.

### i18n boundary

**The core returns codes and structured data only. All user-facing text is produced by `presentation.py` and `i18n.py`.**

| Core output | How it becomes text |
|---|---|
| `HeuristicHit(code, severity, params)` | `i18n.t("reason_<code>", **params)` |
| `HistoryEvent.reasons = [(code, params), ...]` | Same translation, when displayed |
| `kind` = `START` / `EXIT` | `kind_start` / `kind_exit` |
| `severity` | `sev_*` |
| `ProcessMonitor.kill()` -> `"err_gone"` / `"err_denied"` / `"err_failed"` | i18n key with the same name |
| `event_backend_status` = `disabled` / `active` / `unavailable` + `event_backend_error` (code) | `backend_*` / `backend_err_<code>` |

One deliberate exception: **raw OS exception messages** (`event_backend_detail`, `last_error_detail`) are displayed as-is. They are dynamic external-system data, so there is no application-owned text to translate.

Tests protect this boundary: there is no Cyrillic text or English prose in runtime strings under `core/` and `windows/` (checked through the AST, excluding docstrings); every rule code has templates in both languages, and the translations are genuinely different; RU/EN key sets and placeholders match; and every key referenced by the GUI exists. Guard tests have also been mutation-tested: they catch violations deliberately introduced into the core.

Switching languages at runtime does not leave mixed-language strings behind. The **Event History** tree stores formatted text, so it is rebuilt from `monitor.events` when the language changes. The source of truth is the codes, not the rendered text.

## Process identity

`ProcessKey(pid, create_time)` is the single process-identity criterion. The static-field cache in `PollingSource` uses this key. `ProcessMonitor` compares processes through `same_process` (0.05-second tolerance because WMI and psutil may round creation times differently).

If a PID is reused between polling ticks, the monitor emits **EXIT for the old process + START for the new process** instead of suppressing the new process as a duplicate. If the old process's ancestors cannot be recovered after PID reuse, the EXIT event displays only the reliably known process name.

## Events: WMI + polling

- **Windows, running with administrator privileges:** `Win32_ProcessStartTrace` and `Win32_ProcessStopTrace` are consumed through pywin32 in a separate thread. On START, the application immediately reads the path, command line, and user while the process is still alive. This can capture processes that start and exit between polling ticks.
- **Otherwise (non-Windows, no administrator privileges, or no pywin32):** the application compares `PollingSource` snapshots. The only loss is a delay of up to one polling interval; the available data is otherwise the same. The reason the event backend is unavailable is shown in the status bar.
- **Polling always runs.** It is the only source of CPU, RAM, thread, and handle metrics; OS process events do not provide these values.
- The two sources are deduplicated through a shared `_active` table (`pid -> create_time`). Processes that were already running when the application started are registered from the first snapshot; otherwise, their EXIT events could be missed.

### Why WMI instead of raw ETW?

WMI provides the same underlying kernel process tracing through a documented COM interface exposed by the already-required `pywin32` dependency. Using raw ETW from Python would require either a custom ETW session or a third-party wrapper with limited support.

The trade-off is the administrator requirement and the fact that each event contains only the PID, PPID, and process name.

## History and persistence

- **In memory:** `deque(maxlen=20000)`. The GUI displays up to the latest 3,000 rows (`App.EVENT_ROW_CAP`).
- **On disk:** `systema_history.sqlite3` in the working directory. Writes happen on a separate thread: `add()` does not wait for disk I/O (approximately 4 μs); the writer flushes accumulated events in a single transaction (up to 2,000 rows).
- **Format:** `reasons` is stored as JSON in the form `[[code, params], ...]`. It stores codes rather than translated text, so the database is independent of the interface language.
- **Shutdown:** `close()` waits for the queue to be fully flushed (up to 30 seconds) and returns `True` or `False`. In a stress test, 100,000 consecutive events were written with no losses; draining took approximately 0.6 seconds. The previous 2-second timeout lost 18,450 out of 100,000 events. Before `shutdown()`, the GUI stops and joins the polling thread so that the final `poll()` cannot add an event after the history store has closed.
- **Intentional limitations (documented behavior):**
  - After restarting the application, the **Event History** tab is empty. Previous sessions are not loaded into the GUI, although they remain in the SQLite database, which is appended to across runs.
  - If a write fails (for example, because the disk is full), the current batch is lost. The reason is stored in `HistoryStore.write_error`, but **is not displayed in the GUI**.
  - The write queue has no size limit.
  - The database file is not rotated or automatically cleaned up.

## Background workers

`HashWorker`, `SignatureWorker`, and the SQLite writer each use a separate thread and a queue. The first two also use a cache.

The following guarantees are covered by tests:

- Repeated SHA-256 requests for the same file are served from the cache.
- An inaccessible file returns `<n/a>` instead of hanging.
- A process without an image path gets `<n/a>` instead of displaying “calculating…” forever.
- A callback failure does not kill the worker or corrupt its cache. The result is delivered exactly once, outside the `try` block.
- Workers shut down cleanly using a sentinel value.

## Heuristics and severity levels

There are 10 rules: `office-to-shell`, `browser-to-shell`, `temp-path`, `unusual-path`, `no-image`, `suspicious-cmdline`, `long-cmdline`, `masquerade`, `unsigned`, and `untrusted-signature`. The rule set and its semantics have not changed.

A process's severity is the **maximum severity** among all rules that match it.

`LOW / MEDIUM / HIGH` means that certain heuristics matched. It does **not** mean that the process is malware. The interface states this directly (below the list of reasons on the **Security / File** tab), and the UI does not use the words “malware” or “virus” as labels.

False positives are expected. For example, a legitimate installer launched from `Downloads` may trigger the `temp-path` rule.

SHA-256 is a file-integrity fact. The signature status is based on `WinVerifyTrust` (all errors other than “no signature” are grouped under `untrusted`). The displayed publisher is the file version metadata field `CompanyName`; it is **not** cryptographic proof of the publisher's identity, and the UI labels it accordingly.

The **Network** tab displays a process's connections but does not assess them.

## Interface

The main tabs are **Processes** (tree/list, filtering, and sorting) and **Event History**. For a selected process, the detail tabs are **Overview**, **Security / File**, **Connections**, and **Network**.

Text in **Overview** can be selected with the mouse and copied with Ctrl+C, but cannot be edited. Empty states (no process selected, no connections, no reasons, no parent, or no children) are displayed using localized messages.

### CSV export

The **Export Events** CSV uses machine-readable values for `kind`, `source`, and `severity`; these columns do not depend on the interface language. The `reasons` column contains text in the interface language active at the time of export.

## Run

```bash
pip install -r requirements.txt
python app.py
```

On Windows, run the application as administrator to enable the event-driven backend. Without administrator privileges, it falls back to polling.

## Tests

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

The suite contains **62 tests** and does not require `tkinter` (rendering logic was moved to `presentation.py` specifically to make this possible).

Coverage includes process identity and PID reuse, heuristic rules, hashing and caching, workers (including failing callbacks), history (memory limits, SQLite, event bursts, and restarts), orchestration (WMI/polling deduplication, EXIT events for processes that were already running, PID reuse between ticks, and `<n/a>` for missing hashes), and the i18n boundary.

Not covered by automated tests: the complete GUI (it was launch-tested) and `windows/*`.

## Windows verification checklist (not yet performed)

Run these checks on a real Windows system with administrator privileges, in this order:

1. Run `python app.py`. The status bar should show `Event backend: active (WMI…)`. If it shows `unavailable`, the reason and raw OS message should also be displayed.
2. Run `cmd /c exit` repeatedly: `for /l %i in (1,1,200) do @cmd /c exit`. Confirm that each process produces START/EXIT events with `source = WMI` and no duplicates. Compare this with a run without administrator privileges, where polling may miss some short-lived processes.
3. Set the polling interval to 10 seconds and test a process that starts and exits between ticks. Confirm that it is still detected.
4. Check `ParentProcessID` and the parent chain. Check path, command-line, and user fields for very short-lived processes; `<n/a>` is an expected result in some cases.
5. Test `signature.check` with a known signed file (`notepad.exe`), an unsigned file, and a file with an invalid signature. Compare the statuses and check `CompanyName`.
6. Check `NextEvent` timeout handling when no events are available. Confirm that the application does not enter a busy loop or consume excessive CPU while idle.
7. Close the window. Confirm that the WMI thread stops and the application process does not remain in Task Manager.
8. Check the dark title bar on Windows 10 version 1809 or later and Windows 11. Test switching themes at runtime.
9. Run `build.bat`. Confirm that the executable starts, `windows.*` modules and pywin32 are included in the build, and the UAC prompt appears when required.
10. Check antivirus behavior with the PyInstaller one-file build; false positives are possible.

## Known limitations

- All Windows-related items listed in **Verification status** remain unverified on Windows.
- WMI subscriptions require administrator privileges. Each event contains only the PID, PPID, and process name.
- Signature errors (expired, revoked, or hash mismatch) are not distinguished from one another.
- A Linux/macOS event backend has not been implemented, although the `EventBackend` interface is ready.
- Signature verification is not implemented on Linux or macOS.
- `handles` are available only on platforms where psutil exposes them (Windows).
- The following i18n keys are currently unused but intentionally retained: `col_flags`, `col_handles`, `d_chain`, `d_flags`, and `title`.
- Persistence limitations are described in **History and persistence**.

## Final audit: issues found and fixed

1. Heuristic reasons were stored as ready-made Russian text inside `core`. They were not translated in the English interface and were saved as text in history, SQLite, and CSV. They now use codes and parameters, with translation performed by the UI.
2. Event History rows were formatted only once and did not change when the interface language changed. START/EXIT labels were not localized at all. The history tree is now rebuilt when the language changes.
3. Backend diagnostics and `kill` errors were hard-coded in English in backend code. They now use codes.
4. `core/identity.py` was not used: polling had its own tuple and a different tolerance (`0.001` instead of `0.05`). The application now uses a single `ProcessKey`.
5. EXIT events for processes that were already running when the application started were lost (a regression compared with the old monitor). When a PID was reused between ticks, START was incorrectly suppressed as a duplicate. EXIT events now include the path, command line, user, and hash from the last snapshot.
6. SQLite's `close()` silently lost the tail of the queue after a 2-second timeout (18,450 out of 100,000 events); commits also happened every 50 rows. It now uses larger transactions and waits for the queue to be fully flushed.
7. A shutdown race allowed the polling thread to continue running while the history store was being closed.
8. A callback exception could cause workers to deliver a result again with an incorrect value, corrupt the signature cache, or silently terminate the worker thread. This has been fixed.
9. SHA-256 for processes without an image path could remain stuck on “calculating…” indefinitely.
10. Tests required `tkinter`; rendering logic has been moved to `presentation.py`.
11. `requirements.txt` mixed runtime and development dependencies. These are now separated.
12. The UI did not explain that a severity level is not a verdict. This clarification has been added.
