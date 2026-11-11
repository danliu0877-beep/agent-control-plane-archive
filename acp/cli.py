"""JSON operator interface; all mutations go through canonical domain operations."""

import argparse
import json
from pathlib import Path
import sqlite3
import sys

from .adapters import SyntheticAdapter
from .domain import ACPError, Actor
from .runtime import Runtime
from .store import SCHEMA_VERSION


def read_json(path):
    with Path(path).open(encoding="utf-8-sig") as stream:
        return json.load(stream)


def parser():
    root = argparse.ArgumentParser(prog="python -m acp", description="ACP: canonical records and explicitly configured disposable execution. NOT a sandbox.")
    root.add_argument("--data-dir", help="State directory outside source/Git checkouts; or set ACP_DATA_DIR")
    root.add_argument("--backend-config", help="Explicit guarded synthetic backend JSON configuration")
    root.add_argument("--actor", default="local-operator")
    root.add_argument("--role", choices=["human", "planner", "policy", "controller", "reviewer", "worker", "ci"], default="human", help="Recorded attribution, not authentication")
    root.add_argument("--source", default="local-cli")
    commands = root.add_subparsers(dest="group", required=True)
    commands.add_parser("init")
    board = commands.add_parser('board', help='Loopback-only Principal Control Board; no workers started')
    board.add_argument('--port', type=int, default=8765)
    review_commands=commands.add_parser('review').add_subparsers(dest='action',required=True)
    for name in ('mapping','enrollment','enroll','revoke','show','recover','finalize','execute','retry','supplement','failure'):
        command=review_commands.add_parser(name);command.add_argument('id')
        if name in {'enroll','retry','supplement'}:command.add_argument('--file',required=True)
        if name=='revoke':command.add_argument('--reason',required=True)
        if name=='execute':command.add_argument('--test-only',action='store_true')
        if name=='failure':command.add_argument('--work',required=True);command.add_argument('--attempt',required=True)
    provider_runs = commands.add_parser("provider").add_subparsers(dest="action", required=True)
    provider_create = provider_runs.add_parser("create")
    provider_create.add_argument("--run", required=True, help="Explicit prepared planning run")
    provider_create.add_argument("--provider", choices=["submitted", "openai-responses"], required=True)
    provider_create.add_argument("--model", required=True)
    provider_create.add_argument("--reasoning", required=True)
    provider_create.add_argument("--proposal", help="Explicit imported response, submitted provider only")
    for name in ("show", "response", "execute", "recover"):
        view = provider_runs.add_parser(name)
        view.add_argument("id")
        if name in {"execute", "recover"}:
            view.add_argument("--allow-remote-context", action="store_true")
    controlled = commands.add_parser("controlled").add_subparsers(dest="action", required=True)
    materialize = controlled.add_parser("materialize")
    materialize.add_argument("--plan", required=True)
    materialize.add_argument("--revision", type=int, required=True)
    materialize.add_argument("--work", required=True)
    materialize.add_argument("--executor", required=True)
    controlled.add_parser("binding").add_argument("id")
    for name in ("show", "recover", "execute"):
        command = controlled.add_parser(name)
        command.add_argument("id")
        if name == "execute":
            command.add_argument("--request", required=True, help="Exact immutable attempt contract JSON")
            command.add_argument("--executor", required=True, help="Explicit built-in synthetic executor; no fallback")
    planning = commands.add_parser("plan").add_subparsers(dest="action", required=True)
    for name in ("prepare", "create"):
        make = planning.add_parser(name)
        selection = make.add_mutually_exclusive_group(required=True)
        selection.add_argument("--task")
        selection.add_argument("--resolution")
        make.add_argument("--context", required=True, help="Explicit human approval of this stored package for planning only")
        make.add_argument("--revise", help="Existing plan ID; creates a new immutable revision")
        make.add_argument("--test-only", action="store_true", help="Explicitly label disposable synthetic inputs; never a fallback")
    submit = planning.add_parser("submit")
    submit.add_argument("run_id")
    generate = planning.add_parser("generate")
    generate.add_argument("run_id")
    generate.add_argument("--model", default="gpt-6-astra")
    generate.add_argument("--reasoning", choices=["low", "medium", "high"], default="medium")
    generate.add_argument("--allow-remote-context", action="store_true", help="Explicitly authorize sending this run's approved package to the fixed API endpoint")
    for make in (planning.choices["create"], submit):
        make.add_argument("--proposal", required=True, help="Explicit external proposal file; never a context expansion")
        make.add_argument("--provider", required=True)
        make.add_argument("--model", required=True)
        make.add_argument("--reasoning", required=True)
    planning.add_parser("list")
    planning.add_parser("run").add_argument("id")
    for name in ("show", "decisions", "context-requests", "check-stale"):
        view = planning.add_parser(name)
        view.add_argument("id")
        view.add_argument("--revision", type=int)
        if name == "check-stale":
            view.add_argument("--context", required=True)
    project = commands.add_parser("project").add_subparsers(dest="action", required=True)
    add = project.add_parser("add")
    add.add_argument("--id", required=True)
    add.add_argument("--path", required=True)
    add.add_argument("--disabled", action="store_true", help="Register metadata without enabling task intake")
    project.add_parser("list")
    project.add_parser("show").add_argument("id")
    configure = project.add_parser("configure")
    configure.add_argument("id")
    configure.add_argument("--file", required=True, help="Human-owned aliases/terms/context boundary metadata")
    project.add_parser("metadata").add_argument("id")
    resolver = project.add_parser("resolve")
    resolver.add_argument("request")
    resolver.add_argument("--project")
    resolution = commands.add_parser("resolution").add_subparsers(dest="action", required=True)
    resolution.add_parser("show").add_argument("id")
    context = commands.add_parser("context").add_subparsers(dest="action", required=True)
    for name in ("inspect", "manifest", "show"):
        view = context.add_parser(name)
        view.add_argument("project")
        view.add_argument("--task")
        view.add_argument("--request", default="")
        view.add_argument("--max-files", type=int)
        view.add_argument("--max-file-bytes", type=int)
        view.add_argument("--max-total-bytes", type=int)
    context.add_parser("get").add_argument("id")
    task = commands.add_parser("task").add_subparsers(dest="action", required=True)
    create = task.add_parser("create")
    for name in ("project", "title", "request"):
        create.add_argument("--" + name, required=True)
    intake = task.add_parser("intake")
    intake.add_argument("request")
    intake.add_argument("--project", help="Optional explicit stable project ID")
    task.add_parser("list")
    for name in ("show", "events"):
        task.add_parser(name).add_argument("id")
    transition = task.add_parser("transition")
    transition.add_argument("id")
    transition.add_argument("state")
    transition.add_argument("--reason", required=True)
    plan = task.add_parser("plan")
    plan.add_argument("id")
    plan.add_argument("--file", required=True, help="Complete JSON envelope")
    plan.add_argument("--reason", required=True)
    resolve = task.add_parser("resolve")
    resolve.add_argument("id")
    resolve.add_argument("--reason", required=True)
    resolve.add_argument("--retry-ready", action="store_true", help="Record READY continuation only after ownership is resolved/fenced")
    accept = task.add_parser("accept")
    accept.add_argument("id")
    accept.add_argument("--attempt", required=True)
    accept.add_argument("--file", required=True, help="JSON object: criterion ID to evidence ID")
    accept.add_argument("--reason", required=True)
    approval = commands.add_parser("approval").add_subparsers(dest="action", required=True)
    record = approval.add_parser("record")
    record.add_argument("--task", required=True)
    record.add_argument("--kind", choices=["human", "policy"], required=True)
    record.add_argument("--expires", required=True)
    record.add_argument("--policy-ref")
    revoke = approval.add_parser("revoke")
    revoke.add_argument("id")
    revoke.add_argument("--reason", required=True)
    attempt = commands.add_parser("attempt").add_subparsers(dest="action", required=True)
    create = attempt.add_parser("create")
    create.add_argument("--task", required=True)
    create.add_argument("--approval", required=True)
    attempt.add_parser("show").add_argument("id")
    for name in ("submit", "snapshot", "reconcile", "cancel", "collect", "verify"):
        action = attempt.add_parser(name)
        action.add_argument("id")
        action.add_argument("--scenario", choices=["complete", "running", "unknown", "unsupported"], default="complete", help="Explicit synthetic fixture; never actual execution")
    fence = attempt.add_parser("fence")
    fence.add_argument("id")
    fence.add_argument("--evidence", required=True)
    fence.add_argument("--reason", required=True)
    evidence = commands.add_parser("evidence").add_subparsers(dest="action", required=True)
    add = evidence.add_parser("add")
    add.add_argument("--task", required=True)
    add.add_argument("--attempt")
    add.add_argument("--file", required=True)
    return root


def dispatch(runtime, args, actor):
    from . import awareness, context
    if args.group=='review':
        from . import review,dag
        if args.backend_config:raise ACPError('Review uses no worker backend configuration')
        if args.action=='mapping':return {w:review.criteria(runtime,args.id,w) for w in dag.execution(runtime,args.id)['order']}
        if args.action=='enrollment':return review.enrollment(runtime,args.id)
        if args.action=='enroll':
            config=read_json(args.file)
            if set(config)!={'mapping','max_semantic_retries','expires_at'}:raise ACPError('Closed M11 enrollment configuration required')
            return review.enroll(runtime,args.id,config['mapping'],actor,max_semantic_retries=config['max_semantic_retries'],expires_at=config['expires_at'])
        if args.action=='revoke':return review.revoke(runtime,args.id,actor,args.reason)
        if args.action=='show':return review.show(runtime,args.id)
        if args.action=='recover':return review.recover(runtime,args.id,actor)
        if args.action=='finalize':return review.finalize(runtime,args.id,actor)
        if args.action=='retry':return review.retry(runtime,args.id,read_json(args.file),actor)
        if args.action=='supplement':return review.supplement(runtime,args.id,read_json(args.file),actor)
        if args.action=='failure':return review.execution_failure(runtime,args.id,args.work,args.attempt,actor)
        from .review_provider import SyntheticReviewProvider
        return review.execute(runtime,args.id,SyntheticReviewProvider(testing=args.test_only),actor)
    if args.group == "provider":
        from . import planning, provider_runtime
        from .decision_provider import SubmittedDecisionProvider
        from .openai_decision import OpenAIResponsesDecisionProvider
        if args.backend_config:
            raise ACPError("Provider runtime does not use execution backends")
        if args.action == "create":
            if args.provider == "submitted":
                if not args.proposal:
                    raise ACPError("Explicit proposal file required")
                selected = SubmittedDecisionProvider(Path(args.proposal).read_text(encoding="utf-8-sig"), "submitted", args.model, args.reasoning)
            else:
                selected = OpenAIResponsesDecisionProvider(args.model, args.reasoning)
            provider_runtime.enroll(runtime, args.run, selected, actor)
            provider_runtime.request(runtime, args.run, selected, actor)
            return provider_runtime.show(runtime, args.run)
        state = provider_runtime.show(runtime, args.id)
        if args.action == "show":
            return state
        if args.action == "response":
            return state["response"]
        if state["response"] or state["validation"] or args.action == "recover" and state["dispatch"]:
            return provider_runtime.recover(runtime, args.id, actor)
        config = state["run"]["profile"]
        if config["adapter"] == "SubmittedDecisionProvider":
            wire = state["request"]["wire_request"]
            selected = SubmittedDecisionProvider(wire["submitted_raw"], config["provider"], config["model"], config["reasoning"])
        elif config["adapter"] == "OpenAIResponsesDecisionProvider":
            # This milestone's new operator surface permits only synthetic outbound input.
            if not planning.run_show(runtime, args.id)["input"]["test_only"]:
                raise ACPError("M07 outbound pilot requires explicitly test-only input")
            selected = OpenAIResponsesDecisionProvider(config["model"], config["reasoning"], allow_remote=args.allow_remote_context)
        else:
            raise ACPError("No registered CLI adapter; inspect/recover persisted facts only")
        return provider_runtime.execute(runtime, args.id, selected, actor) if args.action == "execute" else provider_runtime.recover(runtime, args.id, actor, selected)
    if args.group == "controlled":
        from . import controlled
        if args.backend_config:
            raise ACPError("M06 does not permit external backend configuration")
        if args.action == "materialize":
            return controlled.materialize(runtime, args.plan, args.revision, args.work, args.executor, actor)
        if args.action == "binding":
            return controlled.binding_show(runtime, args.id)
        if args.action == "show":
            return controlled.show(runtime, args.id)
        if args.action == "recover":
            return controlled.recover(runtime, args.id, actor)
        return controlled.execute(runtime, args.id, read_json(args.request), actor, executor=args.executor)
    if args.group == "plan":
        from . import planning
        from .decision_provider import SubmittedDecisionProvider
        if args.action == "list":
            return planning.list_plans(runtime)
        if args.action == "run":
            return planning.run_show(runtime, args.id)
        if args.action == "check-stale":
            return planning.compare(runtime, args.id, args.context, args.revision)
        if args.action == "generate":
            from .openai_decision import OpenAIResponsesDecisionProvider
            provider = OpenAIResponsesDecisionProvider(args.model, args.reasoning, allow_remote=args.allow_remote_context)
            return {"run_id": args.run_id, **planning.complete(runtime, args.run_id, provider, actor)}
        if args.action in {"show", "decisions", "context-requests"}:
            record = planning.show(runtime, args.id, args.revision)
            return record if args.action == "show" else record["decisions" if args.action == "decisions" else "context_requests"]
        if args.action in {"prepare", "create"}:
            if args.resolution:
                if args.revise:
                    raise ACPError("Use explicit task for plan revision")
                run = planning.prepare_resolution(runtime, args.resolution, args.context, actor, test_only=args.test_only)
            else:
                run = planning.prepare(runtime, args.task, args.context, actor, plan_id=args.revise, test_only=args.test_only)
            if args.action == "prepare":
                return run
            run_id = run["run_id"]
        else:
            run_id = args.run_id
        # Input errors occur inside provider execution and are auditable failures.
        class Submission(SubmittedDecisionProvider):
            def propose(self, inputs):
                self.raw = Path(args.proposal).read_text(encoding="utf-8-sig")
                return super().propose(inputs)
        provider = Submission(None, args.provider, args.model, args.reasoning)
        return {"run_id": run_id, **planning.complete(runtime, run_id, provider, actor)}
    if args.group == "resolution":
        return awareness.resolution_show(runtime, args.id)
    if args.group == "context":
        if args.action == "get":
            return context.get(runtime, args.id)
        limits = {key: getattr(args, key) for key in ("max_files", "max_file_bytes", "max_total_bytes") if getattr(args, key) is not None}
        package = context.load(runtime, args.project, actor, limits, args.task, args.request)
        return context.get(runtime, package["id"], include_content=args.action == "show")
    if args.group == "init":
        return {"schema_version": SCHEMA_VERSION, "database": str(runtime.store.path), "real_worker_execution": "requires explicit backend configuration and approved attempt"}
    if args.group == "project":
        if args.action == "configure":
            return awareness.configure(runtime, args.id, read_json(args.file), actor)
        if args.action == "metadata":
            return awareness.profile(runtime, args.id)
        if args.action == "resolve":
            return awareness.intake(runtime, args.request, actor, args.project, create=False)
        if args.action == "add":
            return runtime.project_add(args.id, args.path, not args.disabled)
        return runtime.project_list() if args.action == "list" else runtime.project_show(args.id)
    if args.group == "task":
        if args.action == "intake":
            return awareness.intake(runtime, args.request, actor, args.project)
        if args.action == "create":
            return runtime.task_create(args.project, args.title, args.request, actor)
        if args.action == "list":
            return runtime.task_list()
        if args.action == "show":
            return runtime.task_show(args.id)
        if args.action == "events":
            return runtime.events(args.id)
        if args.action == "transition":
            return runtime.transition(args.id, args.state, actor, args.reason)
        if args.action == "plan":
            return runtime.plan(args.id, read_json(args.file), actor, args.reason)
        if args.action == "resolve":
            return runtime.resolve_hold(args.id, actor, args.reason, args.retry_ready)
        return runtime.accept(args.id, args.attempt, read_json(args.file), actor, args.reason)
    if args.group == "approval":
        if args.action == "record":
            return runtime.approve(args.task, args.kind, actor, args.expires, args.policy_ref)
        return runtime.revoke(args.id, actor, args.reason)
    if args.group == "attempt":
        if args.action == "create":
            return runtime.attempt_create(args.task, args.approval, actor)
        if args.action == "show":
            return runtime.attempt_show(args.id)
        if args.action == "fence":
            return runtime.fence(args.id, args.evidence, actor, args.reason)
        if args.backend_config:
            from .kandev import KandevAdapter
            adapter = KandevAdapter(read_json(args.backend_config))
        else:
            adapter = SyntheticAdapter(args.scenario)
        return runtime.adapter_operation(args.id, args.action, adapter, actor)
    return runtime.evidence_add(args.task, args.attempt, read_json(args.file), actor)


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    args = parser().parse_args(argv)
    try:
        if args.group == 'board':
            from .board import serve
            serve(args.data_dir, args.port)
            return 0
        actor = Actor(args.actor, args.role, args.source)
        with Runtime(args.data_dir) as runtime:
            result = dispatch(runtime, args, actor)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (ACPError, OSError, sqlite3.Error, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
