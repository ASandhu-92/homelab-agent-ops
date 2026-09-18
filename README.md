# homelab-agent-ops

The harness I use to let AI coding agents (Claude Code and Codex CLI) operate a home lab that
runs the household's DNS, media and home automation. It is the part of the setup that decides
what an agent may run, when it has to stop and ask, how much context it has left, and how two
agents share work without stepping on each other. Everything here has been in daily use since
mid-2026; the tests are the ones that caught real bypasses.

The lab is two Proxmox nodes, two Fedora workstations, a handheld console and about 100
containers. Agents reach other hosts only through Teleport short-lived certificates, secrets sit
in SOPS-encrypted files, and a deny-only hook stands between the model and the shell. The names
in this repo (`hv-1`, `workstation-a`, `ops-agent`, `192.0.2.x`, `example.com`) are placeholders
for the real ones.

## What is here

```
hooks/
  guardrails/guard.py        deny-only PreToolUse hook: parses the command, peels wrappers,
                             descends into bash -c / eval / xargs / $(...) / tsh ssh, applies rules
  guardrails/policy.json     the rules: Teleport-only, no partition writes, media drives never
                             deleted, secrets never read into a transcript, no pct/qm state changes
  guardrails/test_guard.py   152 cases in four suites; the MATCHER and REMOTE suites are the ones
                             that matter
  context-bracket.py         UserPromptSubmit hook that tells the model how much context is left,
                             only on transitions, 0 tokens otherwise
  test_context_bracket.py    unit tests plus an end-to-end run against a fake transcript
skills/
  task-ledger/SKILL.md       claim / heartbeat / release / steal protocol for sharing tasks
                             between Claude Code, Codex and a local model
  task-ledger/lease_sim.py   two workers, one task, every 409 and 422 the protocol produces
docs/
  orchestration.md           phases, roles, delegation rules, parallelism
  memory.md                  the index-plus-topic-files memory, save/skip, dates, pruning
```

Run the tests with nothing but Python 3:

```
python3 hooks/guardrails/test_guard.py       # PASS 152/152 guard cases
python3 hooks/test_context_bracket.py        # 5 tests
python3 skills/task-ledger/lease_sim.py      # prints the claim/steal sequence
```

## How it fits together

```
 operator (browser IDE, tmux)
      |
      v
 +-----------------------------+      read-only tools, own allowlist
 |  orchestrator session       |----> scout / plan-verifier / security-reviewer
 |  (Claude Code or Codex)     |----> executor / mech-executor  (write, isolated worktree)
 |                             |----> verifier                   (runs tests, cannot edit)
 +-----------------------------+
      |  every Bash call
      v
 +-----------------------------+   exit 2 + reason on a hit; 0 otherwise
 |  guard.py  (policy.json)    |   fails CLOSED to built-in rules if the policy is unreadable
 +-----------------------------+
      |  allowed
      v
 tsh ssh ops-agent@<node>  ---->  hv-1 / hv-2 / workstation-a / workstation-b / console
 sops -d secrets/...       ---->  decrypt on use, nothing plaintext on disk
 curl 192.0.2.10:8099/tasks -->  the task ledger (who owns what right now)

 memory index (10 KB, read every session) --> topic files (read on demand)
 context-bracket hook --> "<context-bracket>[LOW] 14% remaining" injected once per crossing
```

Two harnesses share one guard because Codex cannot rewrite a command from a hook, only refuse
it. So every rule refuses and says what to run instead, and both models see the same message.

## One incident, traced

This is the shape of a routine ticket through the harness, taken from a real one in
September 2026 with names changed.

1. **Request.** The uptime monitor has shown a 401 on one service check for weeks. The operator
   asks why.
2. **Lookup before measuring.** The session reads the memory index (10 KB, always loaded) and
   the service's own guide under `knowledge/services/`. Nothing recorded about this failure.
   The inventory snapshot says the monitor runs on container 912 and reads its API token from
   an `--env-file`.
3. **Read-only tool calls.** A `docker inspect` of the container, piped through `sha256sum`
   so the value never lands in the transcript, gives a different hash from the token in the
   env file on disk. The guard allows both calls; they are reads. A `docker logs` confirms the 401s started the day
   the token was rotated.
4. **Diagnosis.** The token was rotated in the file and the container was restarted with
   `docker restart`. That never re-reads `--env-file`. Only a recreate does. The container had
   been running on the old token for seven weeks.
5. **Fix, gated.** Recreating a container is a state change on a live host, so the session
   presents it: what will run, what it expects to see after. The operator says yes. The session
   runs `docker compose up -d --force-recreate uptime` and the guard allows it (compose is not a
   `pct`/`qm` verb and touches no protected path).
6. **Verification.** `curl -s -o /dev/null -w '%{http_code}'` against the checked endpoint
   returns 200 through the monitor's token. The monitor's own dashboard goes green on the next
   poll. Both outputs are in the transcript, not paraphrased.
7. **Recorded.** One line in the memory index under Landmines: "`docker restart` never re-reads
   `--env-file`; only a recreate does; the monitor ate 7 weeks of 401s", with a link to a topic
   file that has the commands. The next session that touches an env file sees it at start.

The point of the trace is the order. Read first, measure second, ask before changing state,
verify with output, write down what will bite again.

## What I use from others

Two skills in my live harness are not mine and are not in this repo: `unlazy` by Leonxlnx (MIT),
which forces acceptance gates to be written before long autonomous work, and `grill-me`, adapted
from Matt Pocock's skills repo (MIT), which interviews the operator one question at a time before
a plan is written. The role and orchestration model in `docs/orchestration.md` grew out of the
PilotFish orchestration policy pattern, rewritten for this estate. The `context-mode` and `rtk`
plugins handle output compression and are separate projects.

## What this does not do

- It is not a sandbox. The guard is a deny list with a tested matcher, not a capability system.
  A model with shell access and enough determination can still find a path around a deny list;
  the tests are the record of the paths found so far.
- It does not decide when to stop a runaway agent. That is the operator, watching tmux.
- It does not cover secrets that live in a running container's environment. The `secrets`
  rule is path-based; `docker inspect` and `docker exec` are not on it. Compare hashes, do not
  print values.
- It has no UI. Everything is hooks, JSON and Markdown.
- The rules are for one estate. `policy.json` names my protected paths and my Teleport nodes;
  you would edit every path in it before using it.

## About

Written between June and September 2026, drafted with Claude Code, reviewed, tested and
maintained by me. The guard's two revisions each came from a fresh-context verifier being asked
to break it and succeeding, which is why the test file is longer than the rule list. MIT licence.
