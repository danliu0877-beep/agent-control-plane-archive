"""Input-only decision boundary. No execution backend, filesystem or network tools."""
from dataclasses import dataclass
from typing import Protocol

from .domain import ACPError, require


class ProviderFailure(ACPError):
    """A received but unusable provider response retained for audit."""
    def __init__(self, reason, raw, metadata):
        super().__init__(reason)
        self.raw, self.metadata = raw, metadata


@dataclass(frozen=True)
class ProviderOutput:
    raw: str | bytes
    metadata: dict


class DecisionProvider(Protocol):
    def propose(self, planning_input: dict) -> ProviderOutput: ...


class RecoverableDecisionProvider(DecisionProvider, Protocol):
    """Optional trusted-adapter protocol; capabilities never imply delivery proof.

    reconcile is lookup-only and returns (ProviderOutput, exact ACP binding) or
    None. Native IDs stay in output metadata. No method may regenerate a reply.
    """
    def durable_profile(self) -> dict: ...
    def reconcile(self, request_receipt: dict) -> tuple[ProviderOutput, dict] | None: ...


class SubmittedDecisionProvider:
    """Explicit external proposal import, not an authenticated model invocation.

    Operator records model/effort provenance. ACP never falls back on failure.
    Transport to an isolated model remains external; this adapter has no tools.
    """
    def __init__(self, raw, provider, model, reasoning):
        self.raw = raw
        self.metadata = {"provider": provider, "model": model, "reasoning": reasoning,
                         "transport": "explicit-submission", "provenance": "operator-attested",
                         "usage": None}

    def propose(self, planning_input):
        return ProviderOutput(self.raw, dict(self.metadata))

    def durable_request(self, planning_input):
        return {"planning_input": planning_input, "submitted_raw": self.raw, "provenance": self.metadata}


class SyntheticDecisionProvider:
    """Test fixture only; never selected by CLI or as a fallback."""
    def __init__(self, raw, *, testing=False):
        require(testing is True, "SyntheticDecisionProvider is test-only")
        self.raw = raw

    def durable_profile(self):
        return {"adapter": "SyntheticDecisionProvider", "provider": "synthetic-test-only", "model": "fixture",
                "reasoning": "deterministic", "external": False, "reconcile": False,
                "idempotency": False, "raw_kind": "proposal"}

    def propose(self, planning_input):
        require(planning_input.get("test_only") is True, "Synthetic planning forbidden for real inputs")
        return ProviderOutput(self.raw, {"provider": "synthetic-test-only", "model": "fixture",
                                      "reasoning": "deterministic", "provenance": "test"})
