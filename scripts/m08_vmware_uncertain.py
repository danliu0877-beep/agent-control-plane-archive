"""Real-VM fault injection: missing positive observer receipt forbids retry.

The artificial query failure is not evidence of a VMware boundary failure.
No canonical stop reissue or retry; stopped diagnostic VM is retained.
"""
import json
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from acp import isolation
from acp.domain import ACPError
from scripts.m08_vmware_integration import setup, fresh_readback, CONTROL


def main():
    root, runtime, host, binding, approval = setup()
    report = {"root": str(root), "fault": "positive post-stop observer unavailable"}
    attempt = None
    try:
        attempt = runtime.attempt_create(binding["task_id"], approval["id"], CONTROL)["id"]
        isolation.reserve(runtime, attempt, host, CONTROL)
        for name in ("clone", "start", "prepare", "tree"):
            isolation.operation(runtime, attempt, name, host, CONTROL)
        isolation.cancel(runtime, attempt, CONTROL)
        original = host.probe.observe
        def missing_positive_observation(vmx):
            raise RuntimeError("INJECTED positive observer unavailable")
        host.probe.observe = missing_positive_observation
        try:
            isolation.operation(runtime, attempt, "stop", host, CONTROL)
            raise AssertionError("Unknown stop observation was accepted")
        except RuntimeError:
            pass
        finally:
            host.probe.observe = original
        owned = isolation.instance(runtime, attempt)
        vmx = Path(owned["vmx"])
        # Independent cleanup observation proves the fixture left no live VM.
        # It is NOT inserted as a canonical fence or completion receipt.
        witness = host.probe.witnesses[vmx]
        report["diagnostic_cleanup"] = {"exact_vmx": str(vmx),
            "same_process_handle_signaled": witness.ceased(), "host_state": original(vmx)}
        assert report["diagnostic_cleanup"]["same_process_handle_signaled"]
        assert report["diagnostic_cleanup"]["host_state"]["state"] == "powered_off"
        for action in (lambda: isolation.record_fence(runtime, attempt, CONTROL),
                       lambda: runtime.resolve_hold(binding["task_id"], CONTROL, "uncertain retry test", retry_ready=True)):
            try:
                action()
                raise AssertionError("Unknown ownership permitted fence/retry")
            except ACPError:
                pass
        host.close()
        runtime.close()
        recovered = fresh_readback(root, attempt)
        assert recovered["disposition"] == "EXECUTION_OWNERSHIP_UNCERTAIN" and not recovered["retry_eligible"]
        assert recovered["pending"] and not recovered["automatic_retry"]
        report.update(result="PASS", attempt=attempt, canonical_readback=recovered,
                      uncertain_retry="DENIED", duplicate_retry="NONE", automatic_stop_reissue=False)
    except BaseException as exc:
        report.update(result="NOT PASSED", error=str(exc))
        if attempt:
            try:
                host.probe.cli("stop", Path(isolation.instance(runtime, attempt)["vmx"]), "hard")
                report["failure_cleanup_requested"] = True
            except Exception as cleanup:
                report["cleanup_error"] = str(cleanup)
        raise
    finally:
        host.close()
        runtime.close()
        path = root / "uncertain-report.json"
        path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps({"report": str(path), "result": report.get("result"), "error": report.get("error")}))


if __name__ == "__main__":
    main()
