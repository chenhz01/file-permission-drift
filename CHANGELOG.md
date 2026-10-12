# Changelog — file-permission-drift

All releases are local drafts; no remote operations are performed.

## v0.1.1 — 2026-10-13

Fixed:
- dead scaffolding line removed from self_test case a08 (leftover from the
  first draft, caught in the round-2 self-review).

Changed:
- self_test expanded to 64 cases across functional / exception / extreme-edge
  categories (scaffold v2 four defenses: SystemExit capture, Unicode-safe
  matching, Windows newline-safe fixtures, SUMMARY last line).
- README: Performance numbers re-measured via the shipped `bench` subcommand
  with reproducible command column.

## v0.1.0 — 2026-10-13

Added:
- Initial local draft: baseline capture (`scan`), structural validation (R0–R2),
  drift reconciliation with widened-write/read classification (W1/W2/D1) and
  churn detection (A1/A2), `--strict` exit-code escalation, argparse CLI
  (`scan` / `validate` / `check` / `bench`) and scaffold-v2 self_test.
