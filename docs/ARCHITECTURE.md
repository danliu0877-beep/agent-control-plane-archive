# Architecture in the frozen M12 snapshot

ACP separates human authority from proposals, execution observations and acceptance.

1. `runtime.py` / `store.py` hold projects, tasks, append-only events and immutable approval/execution records in SQLite v9.
2. `awareness.py` / `context.py` resolve projects and load bounded context. Repository text is data, not authority.
3. `planning.py` / `provider_runtime.py` validate planning proposals and preserve receipt/dispatch/result distinctions.
4. `controlled.py` implements explicit synthetic execution; `dag.py` models dependencies and bounded capacity.
5. `isolation.py` / `vmware_host.py` model exact disposable environments and terminal fencing. Included VMware helpers are historical, host-specific integration code with an example lab path.
6. `review.py` / `review_schema.py` separate review findings, work acceptance, limited retry and final plan acceptance.
7. `board.py`, `board_read.py`, `board_commands.py` and local assets expose a loopback-only projection and closed command surface over those APIs.

M12 uses standard-library Python. Optional OpenAI/Kandev transport adapters exist, but their presence is not live certification. The later M13A branch is intentionally not merged into this candidate because its own status remains incomplete and pending independent review.

Historical milestone reports contained local evidence and private project context. They are not redistributed here. This concise map describes source organization and does not reconstruct missing evidence or elevate historical claims.
