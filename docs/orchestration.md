# Orchestration

How one main-session agent plans work, hands bounded pieces to cheaper or fresher subagents,
and keeps the final judgment for itself. The point is not to delegate everything. It is to spend
expensive reasoning on judgment and route the volume work to cheaper workers, then protect the
result with contracts and verification instead of with a bigger model.

## Not everything needs ceremony

Small, local, already-understood work gets done directly. The lifecycle below is for work that is
large, ambiguous, architectural, risky, or spread across many surfaces. Running the full ritual on
a one-line fix is its own failure mode, and it is the one I hit most often when I first set this
up.

## The five phases

Work moves through five phases. Each has a gate it must pass to enter, and a set of delegation
that is allowed in that phase (allowed, not required).

| Phase | Gate to enter | Who may be dispatched |
|---|---|---|
| Discovery | The question, the allowed scope, the evidence format and the stop condition are stable. The answer may still be unknown. | Read-only scouts on separate evidence surfaces. Their findings reduce planning uncertainty; they decide nothing. |
| Plan | Evidence is in. | The main session writes one plan: outcome, non-goals, scope, dependencies, ownership, sequence, verification, budget, stop conditions. A read-only plan-verifier may attack it. |
| Approval | The plan is written. | For large or risky work, present it and wait for an explicit yes. A broad opening request is not approval of a plan the user never saw. No source edits before that yes. |
| Execution | The contract is stable: scope, exclusive ownership, constraints, done-criteria, integration, verification. | Write-capable executors: mechanical, general, or security. |
| Verification | The change is complete enough to test as a claim. | A fresh-context verifier tries to refute the work before it is reported done. |

The gates only brake. You do not write a plan while discovery is still moving. You do not
dispatch a writer before the contract is stable. You do not report done before verification.
Skipping a gate is where the expensive mistakes live.

## The roles

Roles differ by what they can touch and what judgment they are trusted with. Access is enforced
by tool allowlists in the role definition, not by asking nicely in the prompt.

- **Scout (read-only).** Bounded reconnaissance on one evidence surface. Returns facts with
  file and line references, not decisions. Cannot write, so several can share a workspace.
- **Plan-verifier (read-only).** Fresh context. Given a plan, returns READY or REVISE with
  reasons. Never implements. Its allowlist has no write tools.
- **Executor (write, local judgment).** Bounded decisions inside a stable contract: naming,
  structure, error handling to match the codebase. Owns its files exclusively.
- **Mechanical executor (write, no judgment).** Fully specified repetition. "Apply this exact
  transform in these 30 places."
- **Security-reviewer (read-only) and security-executor (write).** Security work is split.
  Before approval only the reviewer touches it; it gathers evidence about authentication,
  secrets, crypto, validation, hardening. After approval the stable contract goes to the
  executor. Sending pre-approval security work to a general executor is a defect.
- **Verifier (can run, cannot edit).** Fresh context. Keeps the ability to run tests so it can
  reproduce a result, but its job is to refute. Returns CONFIRMED or REFUTED.

The two verifiers are not interchangeable. A plan-verifier with test-running powers starts
implementing; a verifier without them cannot reproduce a failure. Keep the allowlists distinct.

## Delegation rules

- **Spec in one shot.** Every delegation carries goal, constraints, done-criteria, relevant paths,
  and the reason. A worker that knows the intent makes better local calls than one following a
  checklist.
- **Cheapest capable tier first.** Start with the least powerful role that could plausibly
  succeed. Model routing belongs to the role definition; do not override it per call.
- **Two failures, then escalate.** After two failed attempts at a tier, go up one tier or take
  the work over. A third identical retry is waste.
- **Never delegate the final judgment.** Framing, architecture, resolving ambiguity, plan
  synthesis, integration, and any call the user asked you to make stay in the main session. So
  does a single-file read you need right now, and a single unknown bug: diagnosis, tracing and
  the first minimal fix are one reasoning chain, not a scout-then-executor pipeline.
- **Scout findings are inputs, not verified outputs.** When a decision hangs on one scouted fact,
  re-check it. The verifier gate covers executor work, not reconnaissance.
- **Apply the dispatch brake.** Do not fan out when workers would keep depending on evidence the
  main session is still producing, when ownership would overlap, when nobody clearly owns
  synthesis or verification, or when integration would cost more than the parallelism saves.

## Parallelism

- **Background by default.** If the main session can make progress before a subagent returns,
  launch it in the background and keep working. Two or more independent agents all go to the
  background. Foreground only when the very next action cannot proceed without the result.
- **Writers get their own workspace.** Every write-capable agent in a parallel batch gets an
  isolated checkout (a git worktree) and is told not to touch the shared one. Isolation has a
  harvest obligation: when the writer finishes, integrate its changes. An uncollected workspace
  is silently lost work.
- **Collect before you synthesise.** Gather every background result before starting dependent
  work or writing the final answer. A half-collected batch produces a confident, wrong
  conclusion.
- **Long-running processes belong to the orchestrator.** A subagent that detaches a long process
  loses it: no task id, no captured output, no completion signal. Have it hand back the exact
  command, working directory and inputs, and run it yourself under tracking.
- **Do not judge liveness from host signals.** A busy remote agent burns no local CPU and flushes
  its transcript lazily. "No process, stale file" proves nothing. Send it a message.

## Why this shape

Every rule here came from a specific failure that happened without it: a plan approved that the
user never saw, two workers editing the same file, an executor sent to do security work, a "done"
report that had not been tested, a long job killed mid-run by a suspicious parent. The lifecycle
is the scar tissue.
