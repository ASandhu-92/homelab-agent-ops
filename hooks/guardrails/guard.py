#!/usr/bin/env python3
"""harness-guard: a deny-only guardrail hook for AI coding agents.

Reads a Claude-Code-shaped PreToolUse hook payload on stdin and decides whether
the Bash command inside it may run. It is written to be shared by Claude Code
and Codex CLI, which is why it never rewrites a command: Codex 0.148 rejects
`permissionDecision: "allow"` and `updatedInput` never reaches it, so a hook can
block a command but cannot correct it. Every rule therefore blocks and explains
the right command in its message, which both harnesses show to the model.

Why argv-head matching: a substring matcher blocks its own policy documents.
Writing a file that merely contains the word `ssh` is not an SSH connection.
Commands are split on shell operators, wrappers are peeled, nested shells are
descended into, and rules are applied to argv[0] of each simple command.

    The matcher is the attack surface, not the rule list. v1 of this file passed
    all 39 rule tests and was still defeated by a one-token prefix: `peel()`
    stripped `timeout` but not its numeric operand, so `30` became argv[0] and
    every rule silently disengaged. `bash -c "..."`, `eval`, `xargs`, `$(...)`
    and `( ... )` were equally invisible. Anything added below must come with a
    matcher test, not only a rule test. See test_guard.py.

    v2 closed the second round, found by a fresh-context audit. Every rule was
    still local-only: `tsh ssh <node> "wipefs -a /dev/sda"` returned ALLOW, and
    `tsh ssh` is the only sanctioned way to reach another host, so the guard
    was blind at exactly the place a destructive command appears. Alongside it:
    `env -S`, `python3 -c`, `busybox`, `/usr/bin/time`, a relative delete after
    `cd`, `cp --target-directory=`, and a command name taken from a variable.

Modes:
  guard.py pretooluse          exit 2 + stderr  -> the harness blocks, model sees stderr
  guard.py permissionrequest   JSON decision    -> the harness vetoes the escalation

Policy selection: the built-in path, or `--policy PATH` on argv. There is no
environment override. An earlier `HARNESS_GUARD_POLICY` variable was removed:
a variable that re-points the guard at a policy of the caller's choosing is a
bypass, not a test seam. The hook command line is root-owned and never carries
`--policy`; the test suite does.

Fail behaviour: an unreadable or unparseable policy does NOT disable the guard.
It falls back to FALLBACK_POLICY below, the hard rules compiled in, so a typo in
policy.json cannot silently permit `wipefs`. Only a crash in the matcher AND in
the fallback exits 0, because bricking the harness outright is its own kind of
failure.
"""

import json
import os
import re
import shlex
import sys

DEFAULT_POLICY = "/usr/local/lib/harness-guard/policy.json"

# The home directory the guard normalises `~` and `$HOME` against. The hook runs
# as the agent user, so the environment value is right; the default matches the
# paths in policy.json for the test suite.
HOME = os.environ.get("HOME") or "/home/ops"

MAX_DEPTH = 6

ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
REDIRECT = re.compile(r"(?:>>?|<)\s*([^\s;|&]+)")
DURATION = re.compile(r"^\d+(?:\.\d+)?[smhd]?$")
STRING_LIT = re.compile(r"'([^'\\]{2,}?)'|\"([^\"\\]{2,}?)\"")

WRAPPER_VALUE_OPTS = {
    "sudo": {"-u", "--user", "-g", "--group", "-p", "--prompt", "-C", "--close-from",
             "-r", "--role", "-t", "--type", "-U", "--other-user", "-h", "--host"},
    "doas": {"-u", "-C"},
    "nice": {"-n", "--adjustment"},
    "ionice": {"-c", "--class", "-n", "--classdata", "-p", "--pid"},
    "chrt": {"-p"},
    "taskset": {"-p"},
    "timeout": {"-s", "--signal", "-k", "--kill-after"},
    "time": {"-o", "--output", "-f", "--format"},
    "env": {"-u", "--unset", "-C", "--chdir", "-S", "--split-string"},
    "stdbuf": {"-i", "-o", "-e"},
}
XARGS_VALUE_OPTS = {"-I", "-i", "-n", "-P", "-L", "-d", "-E", "-s",
                    "--replace", "--max-args", "--max-procs", "--delimiter"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "busybox"}
SHELL_CMD_FLAGS = {"-c", "-lc", "-ic", "-lic", "-ilc", "--command"}
INPUT_FLAGS = {"-i", "--input", "-if", "--in"}

# Interpreters whose -c/-e argument is a whole program. Both the payload and
# every quoted string literal inside it are re-evaluated: `os.system('rm -rf
# /mnt/media')` only exposes the delete once the literal is unwrapped.
INTERPRETERS = {"python", "python3", "python2", "perl", "ruby", "node", "php", "lua"}
INTERP_FLAGS = {"-c", "-e", "--eval", "--command"}

# `tsh ssh` (Teleport) is the only remote execution path on this estate, so its
# remote-command argument is re-evaluated under the same rules as a local
# command. btsh is the bot-identity wrapper around the same binary.
TSH_BINS = {"tsh", "btsh"}
TSH_VALUE_OPTS = {"-l", "--login", "-p", "--port", "--cluster", "-i", "--identity",
                  "--proxy", "--user", "-o", "--option", "-J", "--jumphost",
                  "--auth", "--ttl", "--format", "-d", "--bind-addr", "--request-id"}

MESSAGES = {
    "indirect-dispatch": (
        "BLOCKED (indirect-dispatch): the command name comes from a shell variable or an "
        "unexpanded substitution, so the guard cannot see what would actually run. Write the "
        "command out literally."
    ),
    "degraded": "harness-guard is running on its built-in hard rules (policy.json unreadable).",
}


def load_policy(path):
    with open(path) as fh:
        return json.load(fh)


def message(policy, key):
    return (policy.get("messages") or {}).get(key) or MESSAGES[key]


def normalise(command):
    """Expose subshell grouping to the operator splitter.

    `( ... )` and `{ ... ; }` each start a fresh command that v1 never saw. Only
    whitespace-delimited braces are treated as grouping, so
    `docker ps --format '{{.Names}}'` is left alone. Command substitution is
    handled by substitutions(), which does not care about quoting."""
    text = re.sub(r"(^|\s)[({](\s|$)", r"\1 ; \2", command)
    text = re.sub(r"(^|\s)[)}](\s|;|$)", r"\1 ; \2", text)
    return text


def substitutions(text):
    """The insides of `$(...)` and backticks, at any quoting depth.

    A substitution runs whether or not it sits inside double quotes, so this
    scan deliberately ignores quote state, unlike split_operators() below,
    which must respect it."""
    out, i = [], 0
    while i < len(text):
        if text.startswith("$(", i):
            depth, j = 1, i + 2
            while j < len(text) and depth:
                if text[j] == "(":
                    depth += 1
                elif text[j] == ")":
                    depth -= 1
                j += 1
            out.append(text[i + 2:j - 1] if depth == 0 else text[i + 2:j])
            i = j
            continue
        if text[i] == "`":
            j = text.find("`", i + 1)
            if j == -1:
                break
            out.append(text[i + 1:j])
            i = j + 1
            continue
        i += 1
    return [s for s in out if s.strip()]


def split_operators(text):
    """Split on shell operators that are outside quotes.

    A regex split cuts straight through a quoted string, and that is how
    `python3 -c "import os; os.system('rm -rf /mnt/media')"` lost its
    payload: the `;` inside the double quotes ended the command as far as v1 was
    concerned, and the remainder no longer parsed as anything."""
    parts, buf, quote, i = [], [], None, 0
    while i < len(text):
        ch = text[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "'\"":
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch in ";\n":
            parts.append("".join(buf))
            buf = []
            i += 1
            continue
        if ch in "|&":
            j = i + 1
            if j < len(text) and text[j] == ch:
                j += 1
            parts.append("".join(buf))
            buf = []
            i = j
            continue
        buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return parts


def simple_commands(command):
    """Split a shell line into simple commands, as argv lists."""
    out = []
    for part in split_operators(normalise(command)):
        part = part.strip()
        if not part:
            continue
        try:
            argv = shlex.split(part)
        except ValueError:
            argv = part.split()
        if argv:
            out.append(argv)
    return out


def peel(argv, wrappers):
    """Strip env assignments and wrapper commands, operands included."""
    i = 0
    while i < len(argv):
        tok = argv[i]
        if ENV_ASSIGN.match(tok):
            i += 1
            continue
        base = os.path.basename(tok)
        if base not in wrappers:
            break
        value_opts = WRAPPER_VALUE_OPTS.get(base, set())
        i += 1
        while i < len(argv):
            t = argv[i]
            if t in value_opts:
                i += 2
                continue
            if t.startswith("-") or DURATION.match(t):
                i += 1
                continue
            break
    return argv[i:]


def env_split_string(argv):
    """The command line hidden inside `env -S "..."`.

    Read before peel(), because peel treats `-S` as a value-taking option and
    drops the payload with it, which is exactly how `env -S` walked past every
    rule in v1."""
    out = []
    for i, tok in enumerate(argv):
        if os.path.basename(tok) != "env":
            continue
        for j in range(i + 1, len(argv)):
            t = argv[j]
            if t in ("-S", "--split-string") and j + 1 < len(argv):
                out.append(argv[j + 1])
                break
            if t.startswith("--split-string="):
                out.append(t.split("=", 1)[1])
                break
            if not t.startswith("-"):
                break
    return out


def interpreter_payloads(argv):
    """`python3 -c "..."` and friends: the program, and its string literals."""
    if not argv:
        return []
    if os.path.basename(argv[0]) not in INTERPRETERS:
        return []
    out = []
    for i, tok in enumerate(argv[1:], start=1):
        if tok in INTERP_FLAGS and i + 1 < len(argv):
            payload = argv[i + 1]
            out.append(payload)
            for m in STRING_LIT.finditer(payload):
                out.append(m.group(1) or m.group(2))
            break
    return out


def tsh_remote_command(argv):
    """The remote command inside `tsh ssh [flags] <target> [--] <cmd...>`.

    Everything the agent is allowed to do on another host goes through here, so
    this is where a destructive command is most likely to appear. v1 stopped at
    argv[0] == "tsh" and never looked at the far side."""
    if not argv or os.path.basename(argv[0]) not in TSH_BINS:
        return []
    rest = argv[1:]
    i = 0
    while i < len(rest):                      # global flags before the subcommand
        t = rest[i]
        if t in TSH_VALUE_OPTS:
            i += 2
            continue
        if t.startswith("-"):
            i += 1
            continue
        break
    if i >= len(rest) or rest[i] != "ssh":
        return []
    i += 1
    target = None
    while i < len(rest):                      # ssh flags, then the target host
        t = rest[i]
        if t == "--":
            i += 1
            break
        if t in TSH_VALUE_OPTS:
            i += 2
            continue
        if t.startswith("-"):
            i += 1
            continue
        target = t
        i += 1
        if i < len(rest) and rest[i] == "--":
            i += 1
        break
    if target is None:
        return []
    remote = rest[i:]
    if not remote:
        return []
    # Two readings, because tsh joins the remaining argv with spaces and hands
    # the result to the remote shell. `tsh ssh host bash -c 'rm -rf /x'` arrives
    # there as the flat string, so evaluate that; but any argument that still
    # carries whitespace was a quoted payload locally, and evaluating it on its
    # own is what catches the delete the flattening would have hidden.
    out = [" ".join(remote)]
    out += [t for t in remote if " " in t.strip() and t != out[0]]
    return out


def nested_commands(argv):
    """Commands hidden inside another command's arguments."""
    if not argv:
        return []
    base = os.path.basename(argv[0])
    out = []

    if base in SHELLS:
        for i, tok in enumerate(argv[1:], start=1):
            if tok in SHELL_CMD_FLAGS or (
                tok.startswith("-") and not tok.startswith("--") and tok.endswith("c")
            ):
                if i + 1 < len(argv):
                    out.append(argv[i + 1])
                break
    elif base == "eval":
        out.append(" ".join(argv[1:]))
    elif base in ("xargs", "parallel"):
        rest = argv[1:]
        j = 0
        while j < len(rest):
            if rest[j] in XARGS_VALUE_OPTS:
                j += 2
                continue
            if rest[j].startswith("-"):
                j += 1
                continue
            break
        if j < len(rest):
            out.append(" ".join(rest[j:]))
    elif base == "find":
        for i, tok in enumerate(argv):
            if tok in ("-exec", "-execdir", "-ok"):
                tail = []
                for t in argv[i + 1:]:
                    if t in (";", "+", "\\;"):
                        break
                    tail.append(t)
                if tail:
                    out.append(" ".join(tail))

    out += tsh_remote_command(argv)
    out += interpreter_payloads(argv)
    return [c for c in out if c and c.strip()]


def expand(token, cwd=None):
    """Normalise a path-ish token enough to compare it against a protected root.

    `cwd` is the directory a preceding `cd` moved to, so that `rm -rf .` after
    `cd /mnt/media` resolves to the protected root it really names."""
    t = token.replace("$HOME", HOME).replace("${HOME}", HOME)
    if t == "~" or t.startswith("~/"):
        t = HOME + t[1:]
    while "//" in t:
        t = t.replace("//", "/")
    if cwd and not t.startswith("/"):
        t = os.path.normpath(os.path.join(cwd, t))
    return t


def touches_skill_root(argv, raw, policy, cwd=None):
    """True when a read-only command's paths all sit under a skill root.

    Codex loads a skill by shelling out to read SKILL.md, so blocking this turns
    into silent hallucination rather than a visible error."""
    if not argv:
        return False
    if os.path.basename(argv[0]) not in policy["readonly_argv0"]:
        return False
    roots = tuple(policy["skill_roots"])
    hits = 0
    for tok in argv[1:]:
        if tok.startswith("-"):
            continue
        path = os.path.normpath(expand(tok, cwd))
        if path.startswith("/"):
            if not path.startswith(roots):
                return False
            hits += 1
    return hits > 0


def path_tokens(argv, raw, rule):
    """Path-ish tokens, skipping any that a rule marks as an input-only position.

    `--opt=value` carries its value with it: `cp --target-directory=/mnt/...`
    looks like a flag and slipped past v1 entirely."""
    out, skip_next = [], False
    input_flags = INPUT_FLAGS if rule.get("input_flags") else set()
    for tok in argv[1:]:
        if skip_next:
            skip_next = False
            continue
        if tok in input_flags:
            skip_next = True
            continue
        if tok.startswith("-"):
            if "=" in tok:
                out.append(tok.split("=", 1)[1])
            continue
        out.append(tok)
    if rule.get("also_check_redirects"):
        out += REDIRECT.findall(raw)
    return out


def check_rule(rule, argv, raw, policy, cwd=None):
    """Return a message when the rule fires, else None."""
    if not argv:
        return None
    base = os.path.basename(argv[0])
    kind = rule["kind"]

    if kind == "argv0":
        return rule["message"] if base in rule["argv0"] else None

    if kind == "regex":
        if rule.get("argv0") and base not in rule["argv0"]:
            return None
        if not re.search(rule["pattern"], raw):
            return None
        req = rule.get("require_arg_regex")
        if req:
            targets = [expand(t, cwd).rstrip("/") or "/"
                       for t in argv[1:] if not t.startswith("-")]
            if not any(re.match(req, t) for t in targets):
                return None
        need = rule.get("require_path")
        if need:
            tokens = ([expand(t, cwd) for t in argv[1:]]
                      + [expand(t, cwd) for t in REDIRECT.findall(raw)])
            if not any(t.startswith(tuple(need)) for t in tokens):
                return None
        return rule["message"]

    if kind == "path":
        if rule.get("allow_argv0") and base in rule["allow_argv0"]:
            return None
        if rule.get("argv0") and base not in rule["argv0"]:
            return None
        protected = tuple(rule["paths"])
        substring = rule.get("match_substring")

        def hit(tok):
            path = expand(tok, cwd)
            norm = os.path.normpath(os.path.abspath(path))
            for p in protected:
                if p.endswith("/"):
                    # A whole directory: the dir itself, or a glob directly under
                    # it. Files inside are covered by their own prefix entries,
                    # so `~/.ssh/known_hosts` stays readable while `~/.ssh` and
                    # `~/.ssh/*` do not.
                    d = p.rstrip("/")
                    if norm == d or norm == d + "/*" or tok.rstrip("/") == d:
                        return True
                elif path.startswith(p) or norm.startswith(p):
                    return True
            return bool(substring and any(p in path for p in protected if not p.endswith("/")))

        if rule.get("also_check_redirects"):
            for tok in REDIRECT.findall(raw):
                if hit(tok):
                    return rule["message"]
        if rule.get("allow_readonly") and base in policy["readonly_argv0"]:
            return None
        for tok in path_tokens(argv, raw, rule):
            if hit(tok):
                return rule["message"]
        return None

    return None


def evaluate(command, policy, depth=0, cwd=None):
    """None = allow. Otherwise the deny message."""
    if depth > MAX_DEPTH:
        return None
    for sub in substitutions(command):
        msg = evaluate(sub, policy, depth + 1, cwd)
        if msg:
            return msg
    for raw_argv in simple_commands(command):
        for payload in env_split_string(raw_argv):
            msg = evaluate(payload, policy, depth + 1, cwd)
            if msg:
                return msg
        argv = peel(raw_argv, policy["wrappers"])
        if not argv:
            continue
        if os.path.basename(argv[0]) == "cd":
            targets = [t for t in argv[1:] if not t.startswith("-")]
            if targets:
                cwd = expand(targets[0], cwd)
            continue
        if argv[0].startswith("$"):
            return "%s\nCommand: %s" % (message(policy, "indirect-dispatch"),
                                        command.strip()[:400])
        if touches_skill_root(argv, command, policy, cwd):
            continue
        for rule in policy["rules"]:
            msg = check_rule(rule, argv, command, policy, cwd)
            if msg:
                return "%s\nCommand: %s" % (msg, command.strip()[:400])
        for nested in nested_commands(argv):
            msg = evaluate(nested, policy, depth + 1, cwd)
            if msg:
                return msg
    return None


# The hard rules, compiled in, used when policy.json cannot be read or parsed.
# Deliberately a subset: these are the rules whose violation is not
# recoverable. Everything else fails open, so a bad policy file cannot brick the
# harness. test_guard.py asserts every id here also exists in policy.json.
FALLBACK_POLICY = {
    "version": 2,
    "skill_roots": ["/home/ops/.codex/skills/", "/home/ops/.agents/skills/",
                    "/home/ops/.claude/skills/", "/mnt/lab/harness/skills/",
                    "/srv/agents-data/harness/skills/"],
    "readonly_argv0": ["sed", "cat", "head", "tail", "grep", "rg", "awk", "wc", "ls",
                       "stat", "file", "md5sum", "sha256sum", "find", "realpath",
                       "readlink", "du", "diff"],
    "wrappers": ["sudo", "nice", "ionice", "timeout", "time", "env", "nohup", "command",
                 "stdbuf", "setsid", "doas", "chrt", "taskset", "busybox"],
    "rules": [
        {"id": "teleport-only", "kind": "argv0",
         "argv0": ["ssh", "scp", "sftp", "sshpass", "ssh-copy-id"],
         "message": "BLOCKED (teleport-only, fallback policy): direct SSH is banned on this "
                    "estate. Use `tsh ssh ops-agent@<node>`."},
        {"id": "destructive-storage", "kind": "argv0",
         "argv0": ["mkfs", "mkfs.ext4", "mkfs.xfs", "mkfs.btrfs", "mkfs.vfat", "mkfs.fat",
                   "mkfs.ntfs", "sgdisk", "sfdisk", "fdisk", "cfdisk", "parted", "wipefs",
                   "ntfsresize", "blkdiscard", "shred", "cryptsetup", "mkswap", "pvremove",
                   "vgremove", "lvremove"],
         "message": "BLOCKED (destructive-storage, fallback policy): partition-table and raw "
                    "block-device writes belong to the operator."},
        {"id": "dd-to-device", "kind": "regex", "argv0": ["dd"],
         "pattern": "(^|\\s)of=/dev/",
         "message": "BLOCKED (destructive-storage, fallback policy): `dd` writing to a block "
                    "device belongs to the operator."},
        {"id": "raw-device-write", "kind": "path", "argv0": None,
         "paths": ["/dev/sd", "/dev/nvme", "/dev/vd", "/dev/hd", "/dev/mmcblk", "/dev/loop",
                   "/dev/mapper"],
         "also_check_redirects": True, "allow_readonly": True,
         "message": "BLOCKED (destructive-storage, fallback policy): naming a raw block device "
                    "as a write target belongs to the operator."},
        {"id": "media-drives", "kind": "path",
         "argv0": ["rm", "rmdir", "mv", "dd", "shred", "truncate", "tee", "chmod", "chown",
                   "install", "cp", "rsync", "ffmpeg", "tar", "unzip", "ln", "unlink", "gzip",
                   "gunzip", "zip", "7z", "mkdir", "touch", "mkfifo"],
         "paths": ["/mnt/media"], "input_flags": True, "also_check_redirects": True,
         "message": "BLOCKED (media-drives, fallback policy): nothing under /mnt/media* is "
                    "ever deleted or overwritten. Write NEW files to a different destination."},
        {"id": "secrets", "kind": "path", "argv0": None,
         "paths": ["/var/lib/secret-broker/secrets", "/etc/secret-broker.conf",
                   "/mnt/lab/secrets", "/home/ops/.ssh/id_", "/root/.ssh/id_",
                   "/home/ops/.config/sops/age", "/home/ops/.ssh/", "/root/.ssh/",
                   "/home/ops/.config/sops/"],
         "allow_argv0": ["sops"], "match_substring": True, "also_check_redirects": True,
         "message": "BLOCKED (secrets, fallback policy): secret material is never read into a "
                    "transcript. Use the credential broker or SOPS."},
        {"id": "rm-root", "kind": "regex", "argv0": ["rm"],
         "pattern": "-[a-zA-Z]*[rR][a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*[rR]",
         "require_arg_regex": "^(/|~|\\$HOME|/home/ops|/etc|/usr|/usr/local|/var|/opt|/mnt|"
                              "/srv|/boot|/home)/?\\*?$",
         "message": "BLOCKED (rm-root, fallback policy): recursive force-delete of a filesystem "
                    "root or a top-level directory. Name the specific subdirectory."},
        {"id": "proxmox-mutate", "kind": "regex", "argv0": ["pct", "qm"],
         "pattern": "(^|\\s)(pct|qm)\\s+(start|stop|shutdown|reboot|reset|suspend|resume|"
                    "destroy|create|restore|clone|migrate|move[-_]?disk|move[-_]?volume|"
                    "resize|set|rollback|snapshot|delsnapshot|template|unlock|push|pull|"
                    "mount|unmount|fsck|fstrim|swap|disk|cloudinit)\\b",
         "message": "BLOCKED (proxmox-mutate, fallback policy): changing container or VM state "
                    "needs explicit operator confirmation. `pct config`, `pct list`, "
                    "`qm config`, `qm list` and `qm status` are allowed."},
    ],
}


def parse_args(argv):
    mode, policy_path = "pretooluse", DEFAULT_POLICY
    i = 0
    while i < len(argv):
        if argv[i] == "--policy" and i + 1 < len(argv):
            policy_path = argv[i + 1]
            i += 2
            continue
        mode = argv[i].lower()
        i += 1
    return mode, policy_path


def main():
    mode, policy_path = parse_args(sys.argv[1:])
    try:
        payload = json.load(sys.stdin)
    except Exception as exc:  # noqa: BLE001 - nothing to guard without a payload
        print("harness-guard: unreadable payload: %s" % exc, file=sys.stderr)
        return 0

    if payload.get("tool_name") != "Bash":
        return 0
    command = (payload.get("tool_input") or {}).get("command")
    if not isinstance(command, str) or not command.strip():
        return 0

    degraded = False
    try:
        policy = load_policy(policy_path)
    except Exception as exc:  # noqa: BLE001 - fail closed on the hard rules
        print("harness-guard: policy unreadable (%s), enforcing built-in hard rules"
              % exc, file=sys.stderr)
        policy, degraded = FALLBACK_POLICY, True

    try:
        verdict = evaluate(command, policy)
    except Exception as exc:  # noqa: BLE001
        print("harness-guard: matcher error: %s" % exc, file=sys.stderr)
        if degraded:
            return 0
        try:
            verdict = evaluate(command, FALLBACK_POLICY)
            degraded = True
        except Exception as exc2:  # noqa: BLE001 - do not brick the harness
            print("harness-guard: fallback matcher error, allowing: %s" % exc2, file=sys.stderr)
            return 0

    if verdict is None:
        return 0
    if degraded:
        verdict = "%s\n%s" % (verdict, MESSAGES["degraded"])

    if mode == "permissionrequest":
        json.dump(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PermissionRequest",
                    "decision": {"behavior": "deny", "message": verdict},
                }
            },
            sys.stdout,
        )
        return 0

    print(verdict, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
