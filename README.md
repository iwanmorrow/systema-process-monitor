on.py`
specifically for this purpose). Covered: identity and PID reuse, heuristic rules,
hashing and caching, workers (including failing callbacks), history (memory
limits, SQLite, bursts, restarts), the orchestrator (WMI/polling deduplication,
handling `EXIT` for previously tracked processes, PID reuse between ticks,
`<n/a>` for hashes), and i18n boundaries. Not covered by automated tests: the
entire GUI (verified via manual execution) and the `windows/*` module.

## Checklist for a real Windows environment (not yet executed)

Run with administrator privileges, in the following order:

1. `python app.py` -> The status bar should display "Event backend: active (WMI…)". 
If it shows `unavailable`, the reason and the raw OS output will be
displayed in the same location.
2. Execute `cmd /c exit` in a loop (`for /l %i in (1,1,200) do @cmd /c exit`):
verify that `START`/`EXIT` events are captured for each, with `source = WMI`,
and no duplicates. Compare this with execution without administrator
privileges (polling will miss some events).
3. Check whether a process that is created and terminates between ticks (with a
10-second interval) is detected.
4. Verify the accuracy of `ParentProcessID` and the process chain; check that
fields such as path, command line, and user are correctly reported (or
correctly identified as `<n/a>` for very short-lived processes).
5. Test `signature.check` using a signed executable (e.g., `notepad.exe`), an
unsigned executable, and one with a corrupted signature; verify the
reported statuses and the `CompanyName` field.
6. Ensure proper handling of `NextEvent` when no events occur (timeout)—verify
that there is no "busy-loop" (i.e., the application should not consume
significant CPU resources while idle). 7. Closing the window: the WMI thread stops, and no process remains in the Task Manager.
8. Dark window title bar (Win10 1809+/Win11); theme switching on the fly.
9. `build.bat`: the executable launches, `windows.*` and pywin32 are included in the build, and a UAC prompt is triggered.
10. Antivirus software and PyInstaller "onefile" builds (false positives are possible).

## Known Limitations

- All points listed under "Verification Status" regarding Windows apply.
- WMI subscription requires administrator privileges; the event provides only the PID, PPID, and process name.
- Signature errors (expired, revoked, or hash mismatch) are not distinguished from one another.
- The event backend for Linux/macOS is not implemented (though the `EventBackend` interface is ready); signatures are not verified on these platforms at all.
- `handles` are reported only where `psutil` provides them (Windows).
- Unused i18n keys that remain in the code: `col_flags`, `col_handles`, `d_chain`, `d_flags`, and `title`.
- Persistence limitations are described in the "History and Persistence" section.

## Changes from the Final Audit (Defects Identified and Fixed)

1. Heuristic descriptions were hardcoded as Russian text within the `core` module; they were not translated in the English interface and were stored as plain text in the history, SQLite database, and CSV files. They have been replaced with codes and parameters, with translation handled in the UI.
2. "Event History" entries were formatted once and did not update when the language was changed; furthermore, `START/EXIT` labels were not localized at all. The system now rebuilds the tree structure to ensure proper localization. 3. Backend diagnostics and the `kill` error message were previously hardcoded as English text within the backend code; they have now been replaced with error codes.
4. `core/identity.py` was not being used (the polling logic had its own tuple structure and a tolerance threshold of 0.001, compared to 0.05 elsewhere). This has been unified into a single `ProcessKey`.
5. EXIT events for processes that were already running at startup were being lost (a regression compared to the previous monitor). Furthermore, if a PID was reused between polling ticks, the corresponding START event was incorrectly suppressed as a duplicate. EXIT events now include the path, command line, user, and hash derived from the most recent snapshot.
6. SQLite: The `close()` operation, triggered by a 2-second timeout, was silently discarding the remainder of the queue (18,450 out of 100,000 entries). Commits were previously occurring every 50 rows; the system now uses "greedy" transactions and ensures the entire queue is flushed before closing.
7. Race condition during shutdown: The polling thread was not being awaited before the history store was closed.
8. Workers: An exception within a callback could lead to a retry with incorrect data, corruption of the signature cache, and the potential silent termination of the thread.
9. For processes lacking a file path, the SHA-256 hash would remain stuck on "calculating..." indefinitely.
10. Tests previously required `tkinter`; rendering logic has now been moved to `presentation.py`.
11. `requirements.txt` contained a mix of runtime and development dependencies.
12. A note clarifying that the "level" does not constitute a formal "verdict" was missing from the UI.
