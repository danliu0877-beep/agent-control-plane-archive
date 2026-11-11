# Agent Control Plane (ACP)

An abandoned experiment in human-controlled, multi-project AI coordination.

I started ACP to reduce the effort of coordinating AI work across projects. After dot became available, I no longer saw a reason to continue developing it. This repository preserves the experiment and its limitations. It is not a finished product or a maintained agent platform.

[繁體中文](README.zh-TW.md)

Released under the [MIT License](LICENSE). Copyright (c) 2026 danliu0877-beep.

## What is here

The M12 source snapshot contains a Python standard-library CLI and local control board, SQLite audit/state records, deterministic project/context resolution, advisory plans, dependency graphs, bounded concurrency, explicit approval/acceptance, and synthetic independent review/retry flows.

A local control record, a worker's success report, a review pass, accepted work, and acceptance of an overall plan are different states. ACP deliberately keeps those distinctions visible.

The default workflow is synthetic. The archived VMware experiment used disposable, isolated test machines. It did not establish safe general-purpose worker execution. Live provider inference is not certified by this snapshot. The later, unfinished M13A provider-certification branch is not included.

## Requirements

- Python 3.12 or later, with SQLite support.
- Git, used by project inspection and tests.
- No third-party Python runtime packages.
- Run from the source checkout. There is no packaged installer or supported hosted service.

Optional historical adapters require their own separately obtained tools. See [third-party notes](THIRD_PARTY.md).

## Try the local record workflow

Use a new state directory **outside every Git checkout**. These commands only create local control records; they do not approve external work.

```powershell
$state = Join-Path $env:LOCALAPPDATA "ACP-Experiment"
python -B -m acp --data-dir $state init
python -B -m acp --data-dir $state project add --id demo --path "$PWD"
python -B -m acp --data-dir $state task create --project demo --title "Test" --request "Synthetic test"
python -B -m acp --data-dir $state task list
python -B -m acp --data-dir $state board --port 8765
```

Open http://127.0.0.1:8765/. The board requires existing initialized state and must remain loopback-only. On Linux or macOS, use an absolute state path outside the checkout in place of `$state`. Only the command-line/offline tests are checked on Linux during release preparation; Windows/VMware behavior is not re-certified here.

For a populated **fake-host, synthetic** demonstration:

```powershell
python -B -m tests.board_demo --output C:\ACP-Synthetic-Demo
python -B -m acp --data-dir C:\ACP-Synthetic-Demo\state board --port 8765
```

The output directory must not exist and must be outside all Git checkouts. This demo uses fabricated host receipts, not real VM isolation evidence.

## Run tests

```sh
python -B -m unittest discover -s tests -v
```

Keep the temporary-directory location outside Git checkouts too. No API credentials or VMware installation are needed for this test command. Integration scripts are not part of default discovery. The sanitized snapshot passes 370 tests with 3 Windows-only skips on Linux. The proposed GitHub Actions workflow has not yet run remotely. See [validation scope](docs/VALIDATION.md).

## Safety and limitations

- Single-user/local research prototype, with no remote or multi-user authentication boundary.
- Do not expose the board publicly or use it for production, real-project autonomous work, or high-impact decisions.
- No automatic merge, push or deployment is demonstrated.
- The VMware helpers retain a fixed **example** laboratory path, `C:\ACP-SYNTHETIC-LAB`. They are historical integration code, not an installation guide. A changed lab/source requires its own validation.
- The optional `vmrun` path passes a disposable guest password in process arguments. Never use production or reused credentials.
- Older isolation approaches were rejected after failing tests. The code is not a general sandbox.
- This abandoned project has no promised support or security-update schedule.

Read [SECURITY.md](SECURITY.md), [architecture](docs/ARCHITECTURE.md), and [publication scope](docs/RELEASE_SCOPE.md) before experimenting.

## License

[MIT License](LICENSE). Copyright (c) 2026 danliu0877-beep. External tools retain their own licenses and terms.
