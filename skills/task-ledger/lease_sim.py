#!/usr/bin/env python3
"""Two workers, one task, an in-memory ledger with the same rules as the HTTP one.

Run:  python3 skills/task-ledger/lease_sim.py

Shows the four things the protocol has to get right: a second claim on a held
task is refused (409), a heartbeat extends only the holder's lease, a lapsed
lease can be stolen and the steal is written down, and a release by the wrong
owner is refused. Time is a counter so the run is deterministic.
"""
import json

CLOCK = {"now": 0}


class Ledger:
    def __init__(self):
        self.rows = {}
        self.audit = []

    def create(self, id, description):
        self.rows[id] = {"id": id, "description": description, "status": "open",
                         "owner": None, "lease_until": None, "result": None}

    def claim(self, id, owner, lease_min=30):
        row = self.rows[id]
        if row["status"] in ("done", "failed"):
            return 409, {"reason": "terminal"}
        held = row["owner"] and row["lease_until"] > CLOCK["now"]
        if held and row["owner"] != owner:
            return 409, {"reason": "held", "owner": row["owner"], "lease_until": row["lease_until"]}
        stolen_from = row["owner"] if row["owner"] and row["owner"] != owner else None
        row.update(owner=owner, status="claimed", lease_until=CLOCK["now"] + min(max(lease_min, 1), 1440))
        if stolen_from:
            self.audit.append({"task_type": "lease-steal", "depends_on": id, "from": stolen_from, "to": owner})
        return 200, {"claimed": True, "lease_until": row["lease_until"], "stolen_from": stolen_from}

    def heartbeat(self, id, owner, lease_min=30):
        row = self.rows[id]
        if row["owner"] != owner:
            return 409, {"reason": "not-owner"}
        row["lease_until"] = CLOCK["now"] + lease_min
        return 200, {"lease_until": row["lease_until"]}

    def release(self, id, owner, status, result):
        row = self.rows[id]
        if row["owner"] != owner:
            return 409, {"reason": "not-owner"}
        if not isinstance(result, str):
            return 422, {"reason": "result must be a JSON-encoded string"}
        row.update(status=status, result=result)
        return 200, {"released": True}


def show(step, code, body):
    print(f"t={CLOCK['now']:>3}  {step:<44} -> {code} {json.dumps(body)}")


if __name__ == "__main__":
    L = Ledger()
    L.create("build-docs", "rewrite the two doctrine docs")
    show("A claims", *L.claim("build-docs", "claude-a1b2c3", lease_min=30))
    show("B claims the same task", *L.claim("build-docs", "codex-9f8e7d"))
    CLOCK["now"] = 20
    show("A heartbeats at t=20", *L.heartbeat("build-docs", "claude-a1b2c3", lease_min=30))
    show("B heartbeats a task it does not own", *L.heartbeat("build-docs", "codex-9f8e7d"))
    CLOCK["now"] = 51
    show("B claims after A's lease lapsed (steal)", *L.claim("build-docs", "codex-9f8e7d"))
    show("A releases, but B owns it now", *L.release("build-docs", "claude-a1b2c3", "done", "{}"))
    show("B releases with an object result", *L.release("build-docs", "codex-9f8e7d", "done", {"v": 1}))
    show("B releases with a string result", *L.release("build-docs", "codex-9f8e7d", "done",
                                                       json.dumps({"verdict": "PASS"})))
    show("A tries again on a terminal task", *L.claim("build-docs", "claude-a1b2c3"))
    print("audit:", json.dumps(L.audit))
