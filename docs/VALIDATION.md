# Validation results

Verified during release preparation on 2026-11-10 and 2026-11-11 UTC using Linux / Python 3.12.14.

- Exact M12 main source: 363 tests, 360 passed, 3 Windows-only skips, 0 failures/errors (59.416 seconds).
- Initial sanitized M12 candidate: 363 tests, 360 passed, 3 Windows-only skips, 0 failures/errors (67.911 seconds).
- Credential-reflection fix (2026-11-11): 373 tests, 370 passed, 3 Windows-only skips, 0 failures/errors (34.249 seconds). Focused transport/provider suite: 45 tests passed (3.737 seconds). Ten added synthetic tests cover HTTP-error omission, untrusted status/close failures, exception chains including active caller contexts, setup/read uncertainty, Unicode/JSON escaping and surrogate errors, exact successful receipts, and no reinvocation.
- Python parsing after the fix: 65 files passed AST parsing. Local Markdown links resolve.
- A proposed GitHub Actions workflow covers Ubuntu and Windows on Python 3.12. It has not run on GitHub; adding the workflow is not a CI pass.

The three skipped cases require Windows file-sharing or NTFS junction semantics. Those platform protections remain unverified by this Linux run.

Default discovery is `python -B -m unittest discover -s tests -v`. It uses temporary state and repositories, synthetic providers/fake VM hosts, and loopback HTTP for the control board. It does not launch real VMware guests or call a live provider. Never run integration scripts merely to satisfy unit-test setup.

Initial attempts using this audit environment's Git-marker temporary directories were rejected by ACP's existing state-location guard. A separate temporary filesystem directory allowed the unchanged guard and test suite to run. Earlier environment-induced failures are not hidden product passes.

The excluded M13A branch was also attempted: 458 tests, with 34 reported failures, 41 errors and 3 skips on this environment. Its certification source-pinning requires Windows, and one harness also requires actual Git checkout metadata. This is an unsuccessful verification attempt, not a Windows regression result or evidence that M13A is ready. No bypass or source relaxation was introduced.

Windows physical VM isolation, live-provider calls, real managed-project execution and the offline desktop's unpushed work are not validated by this run. Historical physical evidence is not redistributed or re-certified here.
