---
name: task-ledger
description: Task-ledger protocol and cross-harness handoff. Claim, heartbeat, release, lease steal. Use when claiming or handing over work between Claude Code, Codex or a local model, or when a /tasks call returns 409 or 422.
---

# The task ledger: how agents claim work and hand it over

Claude Code, Codex CLI and a local model share two substrates. **Plan files** under
`/mnt/lab/plans/<project>/` hold the spec and the results. They are durable, in git, and
both harnesses load them. **The ledger** (`http://192.0.2.10:8099/tasks`, plain LAN HTTP, a small
DuckDB service) holds who owns what *right now*. Files are slow truth; the ledger is fast state.
Do not collapse them into one.

## The `agent_tasks` row

```
id (PK)        text     caller-chosen, e.g. "docs-rewrite-1"
agent          text     the KIND that created it: claude | codex | local
task_type      text     free text; "lease-steal" is reserved for audit rows
description    text
status         text     open | claimed | done | failed | blocked
result         text     a JSON-encoded STRING (an object is rejected with 422)
started_at     timestamp
completed_at   timestamp
owner          text     the SESSION holding it now: "claude-a1b2c3", "codex-9f8e7d"
lease_until    timestamp naive UTC from the ledger's own clock
project        text
depends_on     text     another task id; on a steal row, the stolen id
artifact_path  text     the handoff file
```

`agent` is the kind that created the row; `owner` is the session holding it. Two Claude Code
sessions are two owners. `lease_until` comes from the ledger container's clock and is the single
authority for every lease. Never compare it against your own host's time.

## The protocol: `POST` JSON to four endpoints

| Call | Body | Returns |
|---|---|---|
| `/tasks` | `id`, `agent`, `task_type`, `description` required; `project`, `depends_on`, `artifact_path`, `owner`, `status`, `result` optional | `{"created": true, ...}` |
| `/tasks/<id>/claim` | `owner`, `lease_min` (default 30) | `{"claimed": true, "lease_until": ..., "stolen_from": null}` |
| `/tasks/<id>/heartbeat` | `owner`, `lease_min` | extends your own lease; 409 if you no longer own it |
| `/tasks/<id>/release` | `owner`, `status` (`done`, `failed`, `blocked`), `result`, `artifact_path` | `result` must be a JSON-encoded string, not an object |

```bash
curl -s -X POST http://192.0.2.10:8099/tasks/<id>/claim \
  -H 'Content-Type: application/json' -d '{"owner":"claude-a1b2c3","lease_min":30}'
```

- **A 409 is not an error to retry through.** `{"reason":"held"}` or `{"reason":"terminal"}`
  means the loser backs off and picks different work. Never force a claim, never edit `owner`
  to win one.
- **`lease_min` is clamped to 1 ... 1440** (24 h). Ask for more and you get 24 h. An unbounded
  lease is a task nobody could reclaim.
- **Heartbeat before every long step.** A lapsed lease invites a steal.
- **Steal.** A task past its `lease_until` may be claimed by anyone. The claim returns
  `stolen_from` and writes its own `task_type='lease-steal'` audit row with `depends_on` set to
  the stolen id. Reclaiming is legitimate; hiding it is not.
- **Read.** `GET /tasks?agent=...&status=...&limit=...`, or `POST /query` with a `SELECT`.

`lease_sim.py` in this directory runs the whole sequence against an in-memory ledger with the
same rules: two workers, one task, a refused second claim, a heartbeat, a lapse, a steal with its
audit row, a wrong-owner release, a 422 on an object result.

## Two traps in the raw query endpoint

The ledger also exposes `POST /query` for ad-hoc SQL. Two things about it bit real sessions:

1. It rejects `DROP`, `TRUNCATE` and `ALTER` as a **substring**, even inside a string literal. Any
   prose routed through it ("alter the plan") fails with HTTP 400 and the write is lost. Free text
   goes through the four parameterised endpoints above, never through `/query`.
2. `DELETE` under-reports the rows it removed. Verify with a follow-up `SELECT count(*)`.
   `UPDATE` does return a true count, which is what makes a compare-and-swap possible.

## Handoff: a file plus a task row, never one alone

A row with no artifact is a status update; a file nobody claimed is a note. Write the handoff
under `/mnt/lab/plans/<project>/` and point at it with `artifact_path` on release. Every results
file names the agent and model that produced it; cross-model review is worthless otherwise. End
every bounded task with `VERDICT: PASS` / `FAIL` / `INCONCLUSIVE` plus evidence, and repeat that
verdict in the `result` JSON.

## Invoking Codex on a plan directory: three traps

```bash
cd /srv/agents-data/plans/<project> \
  && codex exec --skip-git-repo-check -s workspace-write \
       -c 'sandbox_workspace_write.network_access=true' "..." < /dev/null
```

1. **The resolved path, not the symlink.** Codex records trust against the real path
   (`/srv/agents-data/...`); `/mnt/lab/...` is a different string and the directory is
   treated as untrusted.
2. **`--skip-git-repo-check` is required.** Plan directories are not git repos, and a trust entry
   does not satisfy the repo check. Without it Codex prints "Not inside a trusted directory" and
   **exits 0**, so a caller checking only the exit status thinks it succeeded.
3. **`writable_roots` was inert in 0.148.0.** Only the workspace is writable, so start Codex in the
   directory it must write into. Without `network_access=true`, `tsh` and every ledger call fail.

Every flag comes **before** `resume`: `codex exec -s ... resume --last`, never
`codex exec resume --last -s ...`.
