# Published snapshot scope

This is a new, history-free snapshot assembled from M12 remote main commit `71fb3276edc102b1ba1133b521720cd3af0ce03c` of the owner's private ACP repository. The original repository and its branches were not changed.

Retained: application source, CLI/web assets, synthetic unit tests and fixtures, schemas, role prompt examples, and the VMware helpers required by the source fingerprint/import graph. Historical lab-path literals were replaced with `C:\ACP-SYNTHETIC-LAB`. A targeted pre-publication fix omits credential-reflecting OpenAI error content and sanitizes transport exceptions, with synthetic regression tests; the offline workflow also clears the correct guest-password environment variable. Domain/runtime authority logic and database schemas were not changed. See SECURITY.md for the fix's limits.

Excluded: the real-project M04/M05 pilot scripts and submitted planning JSON, original private milestone/validation documents, original images, Git history, and the unfinished M13A branch. No private SQLite state, credentials, VM images or installed tools are supplied.

Excluded original documents are retained privately and are not erased or represented as freshly validated evidence. Current public-facing documentation is newly written and deliberately narrower.

The owner approved publication of this clean snapshot under the MIT License with copyright attributed to danliu0877-beep. The original private repository and its history remain private. Desktop-only unpushed work was not checked because that computer was offline during this audit. See VALIDATION.md for platform and verification limitations.

## Historical references

Some preserved diagnostic source comments, such as `scripts/m08_probe.py`, reference historical reports intentionally omitted from this copy. Those reports remain private; their original evidence is unavailable in this snapshot. Do not infer a passing isolation result from a source comment or missing link.

`prompts/` and `schemas/` contain early historical examples. They are not authoritative M12 runtime or provider wire contracts. Use the current validation code and tests to understand accepted inputs.

Optional provider/Kandev model names and version pins are historical. Current availability and interoperability are unverified. No working live configuration is promised.
