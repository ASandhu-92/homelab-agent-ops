# Memory

An agent's context window resets every session. Without a durable memory it re-derives the same
facts every time, and re-derivation is where it re-breaks the things it already learned not to
break. Persistent memory is what turns a year of sessions into cumulative knowledge instead of a
year of first days.

The goal is a memory the agent reads at session start and trusts. That forces two properties: it
must be small enough to read in full, and curated enough that everything in it is still true. A
sprawling, stale memory is worse than none, because it misleads with confidence.

## Index plus topic files

Memory has two layers.

- **An index file.** One line per memory, ending in a link to a detail file. The index is read in
  full at the start of every session, so it has a hard size budget (10 KB here, about 135
  characters a line). It is an index, not a ledger: it says what is known and where to read more.
- **Topic files.** One file per subject with the actual detail: the incident write-up, the
  decision and its rejected alternatives, the environment map. Read on demand, only when the
  index line says the current task needs it.

The always-loaded cost stays bounded and the depth behind each entry is unlimited. A good index
line is a promise ("this is settled, here is the gist, open the file for the mechanics"); the
topic file keeps it. One line from the real index, with names changed:

```
- CrowdSec bans YOUR OWN clients on a 404 burst; 403 + backend "-" is the tell;
  fix = path-scoped whitelist [[landmine-crowdsec-bans-clients-on-404-storm]]
```

The index is grouped by how the entry is used, not by topic: **Landmines** (things that bit
once and will bite again), **Standing facts**, **Open work**, **Working agreements**. Landmines go
first because they are the entries whose absence costs the most.

## Save and skip

The hardest discipline is not saving things. Most of a session is ephemeral and belongs nowhere.

**Save:**
- User preferences and corrections. The things the user had to say twice.
- Environment facts. Which host runs what, ports, canonical paths, version pins that must not
  drift.
- Working agreements. The settled way of doing a recurring thing.
- Completed work that leaves a standing operational fact. Not "I did a task" but "this now works
  this way, and here is what that means next time."
- Incident root causes and fixes. The highest-value category by a wide margin.

**Skip:**
- One-conversation ephemera.
- Anything derivable from code, git history or config. If the agent can read it from the source
  of truth in seconds, a stored copy is a second thing that goes stale.
- Raw command output. Write the conclusion, never the dump.
- Secret values. Never, under any justification. Store the pointer and the fact ("credential X
  lives in the secret store, rotated 2026-07-10"), never the value. A memory file is not an
  access-control boundary.

## Absolute dates

Relative dates are poison in persistent memory. "Fixed yesterday", "the new version", "recently
rotated": every one of these is read in a future session where the reference point has moved,
and the agent silently draws the wrong conclusion. Convert to an absolute date before saving:
"fixed 2026-07-02", "as of 2026-Q2".

## Pruning

When the index nears its cap, prune and consolidate rather than append. Standing facts stay even
after the project that produced them is done; narrative, status lines and duplicates move to an
archive file that is searchable but never auto-loaded. No topic file is deleted in a prune. The
archive is indexed by a local semantic search so "have I seen this before" still has an answer
without the always-loaded cost.

## Verification on recall

A memory records what was true when it was written. Before recommending a file, flag or command
from memory, check it still exists. Two of the landmines in the real index are about memory
itself being wrong: a device-node mapping recorded backwards, and a "read-only mount" that a
later write proved was not.
