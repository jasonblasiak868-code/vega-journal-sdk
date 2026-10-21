# Changelog

## 2026-10-20: fixes found by a source read

These were found by reading the source against its own documentation after release, not by the earlier test and review passes. Each fix has a regression test in
`tests/test_findings_20261020.py` that failed before the fix, and each fix was checked by undoing it and confirming a test fails. Behaviour that changed is listed under "Changed".

### Fixed
- **Concurrent writes could fork the journal file's hash chain**, after which the journal refused to open. Writes now run under a lock (in process) and a file lock (across processes), and a writer whose view of the file is stale is refused instead of writing.
- An idea name could be created twice by racing callers; the check and the record are now one step.
- Cross-process atomicity relies on the file lock and the stale-view check; the stale-view check is covered by a test, the file lock is reasoned rather than tested directly.
