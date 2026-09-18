#!/usr/bin/env python3
"""
context-bracket.py: a UserPromptSubmit hook that warns the model when the
session's context window is running low.

Claude Code never surfaces context usage to the model itself (the statusline
is human-only), so the depletion signal has to be injected. This hook reads
the session transcript's most recent usage line, computes percent-remaining
against the true context window, and emits a compact <context-bracket> nudge
ONLY when the session crosses a bracket boundary. Cost is 0 tokens on steady
prompts, about 30-60 tokens on the handful of transitions.

Window resolution is model-aware. The critical subtlety: the `[1m]` selector
(and thus the 1M window) is a Claude Code CLIENT-SIDE choice that is STRIPPED
from the API model id, so it does NOT survive into the transcript. Usage
lines record the bare id (e.g. `claude-opus-4-8`). The `[1m]` signal only
survives in the CONFIGURED model (env / settings files), so window detection
must consult the configured model, never rely on the transcript name.

Python 3 stdlib only. Any failure exits silently (exit 0). A broken hook must
never block a user's prompt.

Install: add to `~/.claude/settings.json`

    "hooks": {"UserPromptSubmit": [{"hooks": [{"type": "command",
              "command": "python3 /path/to/context-bracket.py"}]}]}
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

STATE_DIR = Path.home() / ".local/state/claude/context-bracket"

# The absolute-token thresholds. Long sessions cost more per turn because the
# whole context is re-read every turn, so past a point it is cheaper to
# `/compact` or `/clear` than to continue. These are the numbers from measuring
# one estate's daily spend; tune them to yours.
ABS_ADVISORY = 120_000
ABS_LOUD = 150_000

# Where the handoff procedure lives, quoted in the HANDOFF nudge so the model
# does not have to guess.
HANDOFF_DOC = "docs/context-handoff.md"


def _window_for_model(s):
    """Context-window size for a model string, or None if unknown.

    Returns 1M when the string carries the 1M selector (`[1m]`) or is a Fable-5
    variant (which runs a 1M window). Everything else is None so the caller can
    continue down the resolution chain to a conservative fallback.
    """
    if not s:
        return None
    m = s.lower()
    if "[1m]" in m or "fable-5" in m:
        return 1_000_000
    return None


def _window_from_config():
    """Recover the window from the CONFIGURED model, where the `[1m]` selector
    actually survives.

    WHY this is needed and why transcript-name matching cannot replace it: the
    `[1m]` suffix is a Claude Code client-side context-window selector and is
    STRIPPED from the API model id recorded in transcripts (they show a bare
    id such as `claude-opus-4-8`, never `...[1m]`). So `_window_for_model()`
    fed a transcript id can only ever return None for a real 1M session. The
    configured model is the only place the signal lives. Do NOT "simplify" this
    back into transcript-id matching. Doing so is exactly the bug this hook
    exists to prevent, and it has already recurred once (a Fable-only fix that
    silently regressed when the standing model became Opus `[1m]`).

    Precedence (matching Claude Code's own): ANTHROPIC_MODEL env, then
    settings.local.json, then settings.json (settings.local wins).
    Returns 1_000_000, or None if no configured model implies a 1M window.
    """
    env_model = os.environ.get("ANTHROPIC_MODEL")
    if env_model:
        w = _window_for_model(env_model)
        if w:
            return w
    home = Path.home()
    for name in ("settings.local.json", "settings.json"):
        try:
            mdl = json.loads((home / ".claude" / name).read_text()).get("model")
        except Exception:
            continue
        if mdl:
            w = _window_for_model(mdl)   # "opus[1m]"/"...fable-5[1m]" -> 1M ; "opus" -> None
            if w:
                return w
    return None


def context_remaining(input_data):
    """Percent context remaining and absolute tokens consumed, from the
    session transcript's last usage line. Returns (pct, absolute_tokens),
    either of which may be None on failure."""
    session_id = input_data.get("sessionId") or input_data.get("session_id") or ""
    cwd = input_data.get("cwd", "")
    if not session_id or not cwd:
        return None, None
    home = Path.home()
    search = Path(cwd)
    session_file = None
    for _ in range(10):
        # Claude Code maps BOTH '/' and '.' to '-' in project dir names; match
        # that mapping so transcripts for dotted cwds are found too.
        project_dir = str(search).replace("/", "-").replace(".", "-").lstrip("-")
        cand = home / ".claude" / "projects" / f"-{project_dir}" / f"{session_id}.jsonl"
        if cand.exists():
            session_file = cand
            break
        if search.parent == search:
            break
        search = search.parent
    if session_file is None:
        return None, None
    try:
        out = subprocess.run(["grep", "-a", '"usage"', str(session_file)],
                             capture_output=True, text=True, timeout=5).stdout
        latest = 0
        model = ""
        for line in out.strip().splitlines():
            try:
                msg = json.loads(line).get("message", {})
                u = msg.get("usage", {})
                # Real current-context load = uncached input + both cache tiers.
                t = (u.get("input_tokens", 0)
                     + u.get("cache_read_input_tokens", 0)
                     + u.get("cache_creation_input_tokens", 0))
                if t:
                    latest = t
                    if msg.get("model"):
                        model = msg["model"]  # newest assistant model wins
            except (json.JSONDecodeError, AttributeError):
                continue
        if not latest:
            return None, None
        # Window resolution, in priority order:
        #   a. explicit manual override (CONTEXT_MAX_TOKENS)
        #   b. model on stdin (forward-compat if the payload ever carries [1m])
        #   c. transcript model id, ALWAYS None for real 1M sessions (see
        #      _window_from_config docstring: the API id drops [1m])
        #   d. configured model (env / settings files), where [1m] survives
        #   e. conservative 200k fallback (pessimistic: over-warns rather than
        #      missing a real depletion, which is the correct failure direction)
        window = (int(os.environ.get("CONTEXT_MAX_TOKENS", 0))
                  or _window_for_model(input_data.get("model"))
                  or _window_for_model(model)
                  or _window_from_config()
                  or 200_000)
        return max(0, 100 - latest * 100 // window), latest
    except Exception:
        return None, None


def bracket(pct):
    """Map percent-remaining to a bracket.

    FRESH    pct >= 30
    ECONOMY  15 < pct < 30
    LOW      10 <= pct <= 15   (boundary inclusive of 15: a 850k/1M load lands
                               at exactly 15% and must still trip the low-context
                               safeguard; over-warning is the correct direction)
    HANDOFF  pct < 10
    """
    if pct is None or pct >= 30:
        return "FRESH"
    if pct > 15:
        return "ECONOMY"
    if pct >= 10:
        return "LOW"
    return "HANDOFF"


NUDGE = {
    "ECONOMY": ("Context ~{pct}% remaining. Be economical: avoid re-reading large files "
                "you've already seen, and keep responses focused."),
    "LOW": ("Context ~{pct}% remaining, LOW. Finish only the current task; no scope "
            "expansion. Flag the low-context state to the user."),
    "HANDOFF": ("Context ~{pct}% remaining, HANDOFF. STOP new work. Write the handoff NOW "
                "per " + HANDOFF_DOC + ", then recommend the user start a fresh session."),
}


def absolute_bracket(latest):
    """Absolute-token bracket, independent of window size.

    Percent-of-window brackets are useless for an absolute-cost rule on a [1m]
    session: percent does not cross 30% until 700k tokens, so the 150-200k
    band gets zero warning on that profile. This bracket fires on absolute
    tokens instead, so it behaves the same on a 200k and a 1M window.
    """
    if latest is None:
        return "NONE"
    if latest >= ABS_LOUD:
        return "LOUD"
    if latest >= ABS_ADVISORY:
        return "ADVISORY"
    return "NONE"


ABS_NUDGE = {
    "ADVISORY": ("Context at ~{k}k absolute tokens, approaching the 150k rule. "
                 "`/compact` if continuing this task."),
    "LOUD": ("Context at ~{k}k absolute tokens, over the 150k rule. `/compact` for this task, "
             "`/clear` for new work. Payback is immediate: `/clear` costs ~45k once vs "
             "150k+ re-read every turn after."),
}


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        return
    sid = (data.get("sessionId") or data.get("session_id") or "unknown")[:64]
    pct, latest = context_remaining(data)
    br = bracket(pct)
    abs_br = absolute_bracket(latest)

    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        state_file = STATE_DIR / f"{sid}.last"
        try:
            prev = json.loads(state_file.read_text())
        except Exception:
            prev = {}
        last_pct = prev.get("pct", "")
        last_abs = prev.get("abs", "")
        state_file.write_text(json.dumps({"pct": br, "abs": abs_br}))
        # opportunistic hygiene: drop state files older than 7 days
        cutoff = time.time() - 7 * 86400
        for f in STATE_DIR.glob("*.last"):
            if f.stat().st_mtime < cutoff:
                f.unlink(missing_ok=True)
    except Exception:
        last_pct = last_abs = ""

    parts = []
    if br != last_pct and br != "FRESH":
        msg = NUDGE.get(br)
        if msg:
            parts.append(f"[{br}] {msg.format(pct=pct if pct is not None else '?')}")
    if abs_br != last_abs and abs_br != "NONE":
        msg = ABS_NUDGE.get(abs_br)
        if msg:
            parts.append(f"[ABS-{abs_br}] {msg.format(k=(latest // 1000) if latest else '?')}")

    if not parts:
        return  # steady state -> zero injection

    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": "<context-bracket>" + " ".join(parts) + "</context-bracket>",
        }
    }))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
