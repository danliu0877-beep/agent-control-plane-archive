"""Backend-independent adapter observations and harmless synthetic implementation."""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from .domain import AttemptState, digest


class Outcome(StrEnum):
    OK = "OK"
    UNKNOWN = "UNKNOWN"
    UNSUPPORTED = "UNSUPPORTED_CAPABILITY"


@dataclass(frozen=True)
class Observation:
    outcome: Outcome
    state: AttemptState | None = None
    backend_task_id: str | None = None
    backend_session_id: str | None = None
    detail: dict = field(default_factory=dict)


class ExecutionAdapter(Protocol):
    name: str
    version: str

    def submit(self, contract: dict, idempotency_key: str) -> Observation: ...
    def get_snapshot(self, idempotency_key: str) -> Observation: ...
    def cancel(self, idempotency_key: str) -> Observation: ...
    def collect_evidence(self, idempotency_key: str) -> list[dict]: ...
    def reconcile(self, idempotency_key: str) -> Observation: ...


class GuardedExecutionAdapter(ExecutionAdapter, Protocol):
    """Optional real-execution boundary, still free of backend-native IDs/types."""
    real_execution: bool
    adapter_version: str
    binding: str
    config: dict

    def prepare(self, contract: dict, project: dict) -> None: ...
    def workspace(self, idempotency_key: str): ...


class SyntheticAdapter:
    """Deterministic simulation, not actual execution or a proof of safety."""

    name = "synthetic"
    version = "1"

    def __init__(self, scenario="complete"):
        if scenario not in {"complete", "running", "unknown", "unsupported"}:
            raise ValueError("Invalid synthetic scenario")
        self.scenario = scenario

    def _observe(self, key):
        if self.scenario == "unsupported":
            return Observation(Outcome.UNSUPPORTED, detail={"reason": "Synthetic capability unavailable"})
        opaque = "demo-" + digest(key)[:24]
        if self.scenario == "unknown":
            return Observation(Outcome.UNKNOWN, backend_task_id=opaque, detail={"simulated": True})
        # Backend-native words stay here and in observation metadata only.
        native = "finished" if self.scenario == "complete" else "busy"
        normalized = {"finished": AttemptState.SUCCEEDED, "busy": AttemptState.RUNNING}[native]
        return Observation(Outcome.OK, normalized, opaque, detail={"native_state": native, "simulated": True})

    def submit(self, contract, idempotency_key):
        if contract["runtime_profile"] != "synthetic":
            return Observation(Outcome.UNSUPPORTED, detail={"reason": "Only synthetic profile is available"})
        return self._observe(idempotency_key)

    def get_snapshot(self, idempotency_key):
        return self._observe(idempotency_key)

    def reconcile(self, idempotency_key):
        return self.get_snapshot(idempotency_key)

    def cancel(self, idempotency_key):
        return Observation(Outcome.OK, AttemptState.CANCEL_REQUESTED, detail={"acknowledged": True, "stopped": False, "simulated": True})

    def collect_evidence(self, idempotency_key):
        return [{"class": "claim", "trust": "unverified", "producer": "synthetic-adapter", "producer_role": "worker", "collector": "ACP", "collection_method": "synthetic adapter response", "outcome": "unknown", "content": {"idempotency_key": idempotency_key, "message": "Simulation only; no worker or tests ran"}}]
