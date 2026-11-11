"""M07 receipt-backed provider lifecycle. No workers or implicit reinvocation."""
import base64
import copy
import json

from . import planning
from .decision_provider import ProviderFailure
from .domain import ACPError, canonical_json, digest, identity, now, require

TABLES = {"provider_runs", "provider_requests", "provider_dispatches", "provider_invocations",
          "provider_responses", "provider_validations", "provider_observations"}


def fact(runtime, table, run_id):
    require(table in TABLES and table != "provider_observations", "Invalid provider fact")
    column = "id" if table == "provider_runs" else "run_id"
    row = runtime.db.execute(f"SELECT * FROM {table} WHERE {column}=?", (run_id,)).fetchone()
    if row is None:
        return None
    record = json.loads(row["record_json"])
    require(digest(record) == row["digest"], "Provider fact digest mismatch")
    return record


def _put(runtime, table, run_id, record):
    require(table in TABLES and table != "provider_runs", "Invalid provider fact")
    runtime.db.execute(f"INSERT INTO {table} VALUES (?,?,?,?)", (identity("PFACT"), run_id, canonical_json(record), digest(record)))


def _observe(runtime, run_id, actor, kind, **details):
    _put(runtime, "provider_observations", run_id, {"kind": kind, "at": now(), "actor": actor.record(), **details})


def profile(provider):
    if hasattr(provider, "durable_profile"):
        result = provider.durable_profile()
    else:
        metadata = getattr(provider, "metadata", {})
        result = {"adapter": type(provider).__name__, "provider": metadata.get("provider", type(provider).__name__),
                  "model": metadata.get("model", getattr(provider, "model", "unspecified")),
                  "reasoning": metadata.get("reasoning", getattr(provider, "reasoning", "unspecified")),
                  "reconcile": False, "idempotency": False,
                  "external": metadata.get("transport") != "explicit-submission", "raw_kind": "proposal"}
    require(type(result) is dict and set(result) == {"adapter", "provider", "model", "reasoning", "reconcile", "idempotency", "external", "raw_kind"}, "Provider capability profile required")
    for key in ("reconcile", "idempotency", "external"):
        require(type(result[key]) is bool, "Provider capability must be explicit boolean")
    for key in ("adapter", "provider", "model", "reasoning"):
        require(isinstance(result[key], str) and 0 < len(result[key]) <= 256, "Provider configuration required")
    require(result["raw_kind"] in {"proposal", "openai-response"}, "Unsupported raw decoder")
    canonical_json(result)
    return result


def enroll(runtime, run_id, provider, actor):
    require(actor.role == "human", "Explicit provider selection required")
    selected = profile(provider)
    with runtime.store.transaction():
        run = planning.run_show(runtime, run_id)
        previous = fact(runtime, "provider_runs", run_id)
        if previous:
            require(previous["profile"] == selected, "Provider run cannot rebind configuration")
        else:
            require(run["result"] is None, "Historical result cannot acquire new invocation")
            previous = {"provider_run_id": run_id, "planning_run_id": run_id, "input_digest": run["input_digest"],
                        "source_task": run["input"]["task_id"], "primary_project": run["input"]["primary_project"],
                        "context_id": run["input"]["context_package"]["id"], "context_digest": run["input"]["context_digest"],
                        "observed_head": run["input"]["context_package"]["repository_state_after"]["head"],
                        "profile": selected, "correlation_key": identity("PCORR"), "at": now(), "actor": actor.record(),
                        "previous_plan_revision": planning.show(runtime, run["input"]["previous_plan_id"])["plan_revision"] if run["input"]["previous_plan_id"] else None}
            runtime.db.execute("INSERT INTO provider_runs VALUES (?,?,?)", (run_id, canonical_json(previous), digest(previous)))
    return show(runtime, run_id)


def request(runtime, run_id, provider, actor):
    require(actor.role in {"human", "controller"}, "Provider controller required")
    with runtime.store.transaction():
        saved = fact(runtime, "provider_runs", run_id)
        require(saved is not None and saved["profile"] == profile(provider), "Provider configuration mismatch")
        run = planning.run_show(runtime, run_id)
        require(run["input_digest"] == saved["input_digest"] and run["input"]["context_digest"] == saved["context_digest"], "Request/context binding mismatch")
        existing = fact(runtime, "provider_requests", run_id)
        if existing:
            return existing
        inputs = copy.deepcopy(run["input"])
        # Optional wire builder is pure configuration, never transport/authentication.
        wire = provider.durable_request(copy.deepcopy(inputs)) if hasattr(provider, "durable_request") else inputs
        record = {"provider_run_id": run_id, "input": inputs, "input_digest": run["input_digest"],
                  "profile": saved["profile"], "wire_request": wire, "request_digest": digest(wire),
                  "correlation_key": saved["correlation_key"], "at": now(), "actor": actor.record()}
        _put(runtime, "provider_requests", run_id, record)
    return record


def _dispatch(runtime, run_id, actor):
    with runtime.store.transaction():
        receipt = fact(runtime, "provider_requests", run_id)
        require(receipt is not None, "Committed request receipt required")
        if fact(runtime, "provider_dispatches", run_id):
            return False
        if fact(runtime, "provider_validations", run_id):
            return False
        _put(runtime, "provider_dispatches", run_id, {"request_digest": receipt["request_digest"], "correlation_key": receipt["correlation_key"],
             "at": now(), "actor": actor.record(), "meaning": "Invocation intent; not proof of send or completion"})
    return True


def _started(runtime, run_id, actor):
    with runtime.store.transaction():
        require(fact(runtime, "provider_dispatches", run_id), "Dispatch intent required")
        _put(runtime, "provider_invocations", run_id, {"at": now(), "actor": actor.record(), "meaning": "About to invoke; delivery remains unproven"})


def _encode(raw):
    if isinstance(raw, bytes):
        return {"encoding": "base64", "data": base64.b64encode(raw).decode("ascii")}
    if isinstance(raw, str):
        return {"encoding": "text", "data": raw}
    return {"encoding": "invalid-type-repr", "data": repr(raw)}


def _decode(raw):
    return base64.b64decode(raw["data"], validate=True) if raw["encoding"] == "base64" else raw["data"]


def receive(runtime, run_id, raw, metadata, actor, *, source="direct", binding=None, error=None):
    require(actor.role in {"human", "controller"}, "Provider controller required")
    encoded = _encode(raw)
    try:
        canonical_json(metadata)
        observed = metadata
    except (TypeError, ValueError):
        observed = {"invalid_metadata_repr": repr(metadata)}
        error = error or "PROVIDER_FAILURE: PROVIDER_METADATA"
    conflict = False
    with runtime.store.transaction():
        saved_request = fact(runtime, "provider_requests", run_id)
        require(saved_request is not None and fact(runtime, "provider_dispatches", run_id), "Request and dispatch facts required")
        exact_binding = {"provider_run_id": run_id, "request_digest": saved_request["request_digest"], "correlation_key": saved_request["correlation_key"]}
        require(source in {"direct", "recovered"}, "Unknown response source")
        if (binding is not None and binding != exact_binding) or (source == "recovered" and binding is None):
            _observe(runtime, run_id, actor, "CONFLICTING_RECOVERY_IDENTITY", binding=binding, raw=encoded, metadata=observed)
            conflict = True
        else:
            record = {**exact_binding, "raw": encoded, "raw_digest": digest(encoded), "metadata": observed,
                      "source": source, "certainty": "RESPONSE_OBSERVED", "error": error, "at": now(), "actor": actor.record()}
            old = fact(runtime, "provider_responses", run_id)
            if old:
                if old["raw"] != encoded or old["metadata"] != observed or old["error"] != error:
                    _observe(runtime, run_id, actor, "CONFLICTING_RESPONSE", candidate=record)
                    conflict = True
            else:
                _put(runtime, "provider_responses", run_id, record)
    require(not conflict, "Conflicting response retained in audit; canonical receipt unchanged")
    return fact(runtime, "provider_responses", run_id)


def _validation(runtime, run_id, actor, *, known_error=None):
    with runtime.store.transaction():
        old = fact(runtime, "provider_validations", run_id)
        if old:
            return old
        saved = fact(runtime, "provider_runs", run_id)
        receipt = fact(runtime, "provider_responses", run_id)
        require(receipt is not None or known_error is not None, "Raw receipt required before validation")
        raw, normalized = None, None
        metadata = receipt["metadata"] if receipt else {"provider": saved["profile"]["provider"]}
        error = known_error or (receipt["error"] if receipt else None)
        if receipt:
            require(digest(receipt["raw"]) == receipt["raw_digest"], "Raw response digest mismatch")
            raw = _decode(receipt["raw"])
        try:
            if not error:
                require(isinstance(metadata, dict), "PROVIDER_METADATA")
                for key in ("provider", "model", "reasoning"):
                    planning.prose(metadata.get(key), key)
                if saved["profile"]["raw_kind"] == "openai-response":
                    from .openai_decision import decode_response
                    output = decode_response(raw, metadata)
                    raw, metadata = output.raw, output.metadata
                require(receipt["raw"]["encoding"] != "invalid-type-repr", "RAW_TYPE")
                normalized = planning.validate(raw, planning.run_show(runtime, run_id)["input"])
        except ProviderFailure as exc:
            error = "PROVIDER_FAILURE: " + str(exc)
        except (ACPError, ValueError, TypeError, KeyError, RecursionError) as exc:
            error = "VALIDATION_FAILED: " + str(exc)
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", "replace") # legacy text audit; exact bytes remain in receipt
        if raw is not None and not isinstance(raw, str):
            raw = repr(raw)
        record = {"validation_id": identity("VAL"), "policy": planning.POLICY,
                  "receipt_digest": digest(receipt) if receipt else None, "raw": raw,
                  "metadata": {"observations": metadata, "started_at": saved["at"], "ended_at": now()},
                  "normalized": normalized, "error": error, "status": "REJECTED" if error else "PASS",
                  "at": now(), "actor": actor.record()}
        _put(runtime, "provider_validations", run_id, record)
    return record


def finalize(runtime, run_id, actor):
    require(actor.role in {"human", "controller"}, "Provider controller required")
    checked = fact(runtime, "provider_validations", run_id) or _validation(runtime, run_id, actor)
    require(checked["policy"] == planning.POLICY, "Validator version mismatch; held")
    planning.finalize(runtime, run_id, checked["raw"], checked["metadata"], checked["normalized"], checked["error"], checked["validation_id"])
    return show(runtime, run_id)


def execute(runtime, run_id, provider, actor):
    require(actor.role in {"human", "controller"}, "Provider controller required")
    saved = fact(runtime, "provider_runs", run_id)
    require(saved is not None and saved["profile"] == profile(provider), "Provider configuration mismatch")
    if fact(runtime, "provider_responses", run_id) or fact(runtime, "provider_validations", run_id):
        return finalize(runtime, run_id, actor)
    request(runtime, run_id, provider, actor)
    # Preflight can prove configuration/authentication failures happened before send.
    if not fact(runtime, "provider_dispatches", run_id) and hasattr(provider, "durable_preflight"):
        try:
            provider.durable_preflight()
        except ACPError as exc:
            _validation(runtime, run_id, actor, known_error="PROVIDER_FAILURE: " + str(exc))
            return finalize(runtime, run_id, actor)
    if not _dispatch(runtime, run_id, actor):
        return recover(runtime, run_id, actor)
    _started(runtime, run_id, actor)
    receipt = fact(runtime, "provider_requests", run_id)
    try:
        if hasattr(provider, "invoke_durable"):
            output = provider.invoke_durable(copy.deepcopy(receipt))
        else:
            output = provider.propose(copy.deepcopy(receipt["input"]))
    except ProviderFailure as exc:
        receive(runtime, run_id, exc.raw, exc.metadata, actor, error="PROVIDER_FAILURE: " + str(exc))
    except Exception as exc:
        # No send guarantee from generic exceptions; preserve uncertainty, never fallback.
        with runtime.store.transaction():
            _observe(runtime, run_id, actor, "PROVIDER_OUTCOME_UNKNOWN", error_class=type(exc).__name__)
        return show(runtime, run_id)
    else:
        receive(runtime, run_id, output.raw, output.metadata, actor)
    return finalize(runtime, run_id, actor)


def recover(runtime, run_id, actor, provider=None):
    require(actor.role in {"human", "controller"}, "Provider controller required")
    state = show(runtime, run_id)
    if state["response"] or state["validation"]:
        return finalize(runtime, run_id, actor)
    if not state["dispatch"]:
        return execute(runtime, run_id, provider, actor) if provider is not None else state
    with runtime.store.transaction():
        _observe(runtime, run_id, actor, "PROVIDER_OUTCOME_UNKNOWN", reason="Dispatch intent without durable response; no reinvocation")
    if provider is not None:
        require(profile(provider) == state["run"]["profile"], "Provider configuration mismatch")
        if state["run"]["profile"]["reconcile"]:
            req = state["request"]
            # Lookup only. Adapter must return exact ACP binding, not a latest response.
            recovered = provider.reconcile(copy.deepcopy(req))
            if recovered is not None:
                output, binding = recovered
                receive(runtime, run_id, output.raw, output.metadata, actor, source="recovered", binding=binding)
                return finalize(runtime, run_id, actor)
    return show(runtime, run_id)


def show(runtime, run_id):
    saved = fact(runtime, "provider_runs", run_id)
    require(saved is not None, "Unknown durable provider run")
    source = planning.run_show(runtime, run_id)
    require(source["input_digest"] == saved["input_digest"], "Provider input binding mismatch")
    req = fact(runtime, "provider_requests", run_id)
    response = fact(runtime, "provider_responses", run_id)
    validation = fact(runtime, "provider_validations", run_id)
    dispatch = fact(runtime, "provider_dispatches", run_id)
    result = json.loads(source["result"]["result_json"]) if source["result"] else None
    hold = None
    if validation and not result:
        if validation["policy"] != planning.POLICY:
            hold = "VALIDATOR_VERSION_MISMATCH"
        previous_plan = source["input"]["previous_plan_id"]
        if previous_plan and planning.show(runtime, previous_plan)["plan_revision"] != saved["previous_plan_revision"]:
            hold = "STALE_PROVIDER_PLAN"
    state = "PLAN_REVISION_FINALIZED" if result and result["plan_id"] else "REJECTED" if result else "VALIDATION_COMPLETED" if validation else "RAW_RESPONSE_RECEIPT_PERSISTED" if response else "PROVIDER_OUTCOME_UNKNOWN" if dispatch else "REQUEST_RECEIPT_PERSISTED" if req else "PROVIDER_RUN_CREATED"
    if hold:
        state = "FINALIZATION_HELD"
    observations = []
    for row in runtime.db.execute("SELECT * FROM provider_observations WHERE run_id=? ORDER BY rowid", (run_id,)):
        value = json.loads(row["record_json"])
        require(digest(value) == row["digest"], "Provider observation digest mismatch")
        observations.append(value)
    return {"provider_run_id": run_id, "run": saved, "state": state, "request": req, "dispatch": dispatch,
            "invocation": fact(runtime, "provider_invocations", run_id), "response": response, "validation": validation,
            "result": result, "observations": observations, "hold_reason": hold,
            "automatic_reinvocation_allowed": False if dispatch else result is None}
