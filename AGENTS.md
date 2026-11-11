# Working on this archived experiment

- Read README.md, SECURITY.md and docs/RELEASE_SCOPE.md before edits.
- Keep work on a separate branch and inspect git status first.
- Do not broaden execution authority, bypass review/approval gates, or silently enable a live provider.
- Use only disposable synthetic inputs for tests. Never add real project data or credentials.
- Preserve the distinction between test results and physical isolation/live-provider evidence.
- Run `python -B -m unittest discover -s tests -v` after changes.
- Report files changed, checks run, failures/skips and remaining limitations.
- Do not merge, publish, deploy or run VM integration scripts without explicit owner approval.
