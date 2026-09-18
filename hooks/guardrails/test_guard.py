#!/usr/bin/env python3
"""Regression tests for harness-guard.

Run:  python3 hooks/guardrails/test_guard.py

Two suites, and the second is the one that matters.

RULES tests ask "does this rule cover this command". MATCHER tests ask "can the
rule be walked around". v1 of this suite had 39 rule cases, all passing, while a
fresh-context verifier defeated every single rule with a one-token prefix,
`timeout 30 ssh ...`, because `peel()` dropped the wrapper but not its numeric
operand. Rule coverage says nothing about matcher coverage. Every payload in the
MATCHER suite is one the verifier actually got through.

The skill-loading cases are not optional either: Codex reads a SKILL.md by
shelling out, and a blocked read fails silently. The model hallucinates instead
of erroring.
"""

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
GUARD = os.path.join(HERE, "guard.py")
POLICY = os.path.join(HERE, "policy.json")

# The home directory policy.json is written for. The guard reads HOME from its
# environment, so the tests pin it rather than depend on who runs them.
TEST_HOME = "/home/ops"

ALLOW, DENY = "allow", "deny"

RULES = [
    # --- skill loading must never be blocked -----------------------------
    (ALLOW, "sed -n '1,240p' /home/ops/.codex/skills/docker-ops/SKILL.md", "skill load, codex root"),
    (ALLOW, "sed -n '1,240p' /home/ops/.agents/skills/impeccable/SKILL.md", "skill load, shared root"),
    (ALLOW, "cat /mnt/lab/harness/skills/secops/SKILL.md", "skill load, harness root"),
    (ALLOW, "cat /srv/agents-data/harness/skills/secops/SKILL.md", "skill load, resolved root"),
    (ALLOW, "head -200 /home/ops/.claude/skills/traefik-ops/SKILL.md", "skill load, claude root"),
    (ALLOW, "grep -n 'apparmor' /mnt/lab/harness/skills/docker-ops/SKILL.md", "skill grep"),
    (ALLOW, "grep -rn tsh /home/ops/.agents/skills/", "recursive skill grep"),
    (ALLOW, "find /mnt/lab/harness/skills -name SKILL.md", "skill find"),
    (ALLOW, "wc -l /mnt/lab/harness/skills/secops/SKILL.md", "skill wc"),
    (ALLOW, "cat /home/ops/.agents/skills/adapt/SKILL.md | head -50", "skill read piped"),
    (ALLOW, "cd /home/ops/.agents/skills/adapt && cat SKILL.md", "skill read after cd"),
    (ALLOW, "cat ~/.agents/skills/adapt/SKILL.md", "skill read, tilde form"),

    # --- teleport-only ---------------------------------------------------
    (DENY, "ssh ops-agent@workstation-b uptime", "plain ssh"),
    (DENY, "scp /tmp/x ops-agent@workstation-a:/tmp/x", "plain scp"),
    (DENY, "sudo ssh root@hv-2 ls", "ssh behind sudo"),
    (DENY, "echo hi && ssh workstation-a ls", "ssh in second clause"),
    (ALLOW, "tsh ssh ops-agent@workstation-b uptime", "tsh ssh"),
    (ALLOW, "tsh scp /tmp/x ops-agent@hv-1:/srv/agents-data/x", "tsh scp"),
    (ALLOW, "ssh-keygen -l -f /home/ops/.ssh/known_hosts", "ssh-keygen is not ssh"),
    (ALLOW, "echo 'never use ssh here' > /tmp/policy-note.md", "the word ssh inside a document"),

    # --- destructive storage --------------------------------------------
    (DENY, "mkfs.ext4 /dev/sdb1", "mkfs"),
    (DENY, "sudo wipefs -a /dev/nvme0n1", "wipefs behind sudo"),
    (DENY, "sgdisk --zap-all /dev/sda", "sgdisk"),
    (DENY, "dd if=/tmp/img.iso of=/dev/sdb bs=4M", "dd to device"),
    (ALLOW, "dd if=/dev/zero of=/tmp/testfile bs=1M count=10", "dd to a regular file"),
    (DENY, "btrfs device delete /dev/sdc /mnt/data", "btrfs device delete"),
    (ALLOW, "btrfs filesystem show", "btrfs read"),
    (DENY, "efibootmgr -B -b 0003", "efi entry delete"),
    (ALLOW, "efibootmgr -v", "efibootmgr listing"),

    # --- media drives ----------------------------------------------------
    (DENY, "rm -f /mnt/media/Movies/x.mkv", "delete from media"),
    (DENY, "mv /tmp/a.mkv /mnt/media2/a.mkv", "overwrite onto media"),
    (ALLOW, "ls /mnt/media/Movies", "reading media"),
    (ALLOW, "find /mnt/media -name '*.mkv'", "listing media with find"),
    (ALLOW, "ffmpeg -i /mnt/media/a.mkv /tmp/out.m4a", "transcode OUT of media"),

    # --- secrets ---------------------------------------------------------
    (DENY, "cat /var/lib/secret-broker/secrets/mcp.header", "reading a broker secret"),
    (DENY, "cp /home/ops/.ssh/id_ed25519 /tmp/k", "copying a private key"),
    (ALLOW, "sudo -n -u broker /usr/local/bin/secret-broker-run mcp-proxy infra", "the broker itself"),
    (ALLOW, "sops -d /mnt/lab/secrets/api.env", "sops is the sanctioned path"),

    # --- rm root ---------------------------------------------------------
    (DENY, "rm -rf /", "rm -rf root"),
    (DENY, "rm -rf /home/ops", "rm -rf a home"),
    (ALLOW, "rm -rf /tmp/scratch-dir", "rm -rf a scratch dir"),
    (ALLOW, "rm -rf /home/ops/.codex/skills/probe", "rm -rf a named subdir"),

    # --- ordinary work must stay fast ------------------------------------
    (ALLOW, "docker ps --format '{{.Names}}'", "docker ps with brace template"),
    (ALLOW, "curl -s http://192.0.2.10:8099/services", "the ledger service"),
    (ALLOW, "git status --short", "git"),
    (ALLOW, "python3 -c 'print(1)'", "python"),
    (ALLOW, "ls /dev/sda", "listing a device is not writing to it"),
    (ALLOW, "sudo -n install -o root -g root -m 0755 /tmp/x /usr/local/lib/harness-guard/guard.py", "the guard's own install"),
    (ALLOW, "timeout 600 python3 /mnt/lab/harness/sync.py --apply", "sync behind timeout"),
    (ALLOW, "nice -n 15 docker ps", "docker behind nice"),
]

# Every payload below is one a fresh-context verifier used to walk around the
# rules while all 39 rule tests were passing. They are the real contract.
MATCHER = [
    # H1: wrapper operands
    (DENY, "timeout 30 ssh ops-agent@workstation-b rm -rf /data", "H1 timeout + numeric operand"),
    (DENY, "timeout 5 mkfs.ext4 /dev/sdb1", "H1 timeout + mkfs"),
    (DENY, "timeout 10 rm -rf /", "H1 timeout + rm -rf /"),
    (DENY, "timeout 5m rm -rf /", "H1 timeout + duration suffix"),
    (DENY, "timeout -s KILL 5 ssh workstation-a ls", "H1 timeout with signal option"),
    (DENY, "nice -n 15 ssh ops-agent@workstation-b ls", "H1 nice with separated value"),
    (DENY, "nice -n15 ssh ops-agent@workstation-b ls", "H1 nice with glued value"),
    (DENY, "ionice -c 3 ssh ops-agent@workstation-b ls", "H1 ionice"),
    (DENY, "sudo timeout 30 wipefs -a /dev/sda", "H1 stacked wrappers"),

    # H2: nested shells and exec-ers
    (DENY, 'bash -c "ssh ops-agent@workstation-b uptime"', "H2 bash -c"),
    (DENY, 'sh -c "ssh ops-agent@workstation-b ls"', "H2 sh -c"),
    (DENY, 'bash -lc "mkfs.ext4 /dev/sdb1"', "H2 bash -lc"),
    (DENY, "eval ssh ops-agent@workstation-b", "H2 eval"),
    (DENY, "xargs -I{} ssh {} ls", "H2 xargs"),
    (DENY, "find /tmp -exec ssh a@b ls ;", "H2 find -exec"),
    (DENY, 'sudo bash -c "rm -rf /"', "H2 wrapper plus nested shell"),

    # H3: substitution and grouping
    (DENY, "echo $(ssh ops-agent@workstation-b whoami)", "H3 command substitution"),
    (DENY, "( ssh ops-agent@workstation-b ls )", "H3 subshell"),
    (DENY, "{ ssh ops-agent@workstation-b ls; }", "H3 brace group"),

    # H4: globs
    (DENY, "rm -rf /*", "H4 glob at root"),
    (DENY, "rm -rf /home/ops/*", "H4 glob under home"),

    # H5: media beyond the obvious mutators
    (DENY, "find /mnt/media -name '*.mkv' -delete", "H5 find -delete"),
    (DENY, "rsync -a --delete /tmp/ /mnt/media/", "H5 rsync --delete"),
    (DENY, "ffmpeg -i /tmp/a.mkv -y /mnt/media/out.mkv", "H5 ffmpeg overwrite in place"),

    # H6: path normalisation
    (DENY, "cat $HOME/.ssh/id_ed25519", "H6 $HOME expansion"),
    (DENY, "cat //var/lib/secret-broker/secrets/foo", "H6 doubled slash"),
    (DENY, "python3 -c \"print(open('/var/lib/secret-broker/secrets/x').read())\"", "H6 path inside a -c payload"),

    # H8: found by the pre-publish review. A skill-root exemption and a
    # filename-prefix secrets rule each left a directory-shaped hole.
    (DENY, "cat /home/ops/.claude/skills/../../.ssh/id_ed25519", "H8 dot-dot out of a skill root"),
    (DENY, "cat /mnt/lab/harness/skills/../../secrets/x", "H8 dot-dot out of the harness root"),
    (DENY, "cat /home/ops/.ssh/*", "H8 glob over the ssh dir"),
    (DENY, "tar czf /tmp/k.tgz /home/ops/.ssh", "H8 tar of the ssh dir"),
    (DENY, "cp -r /home/ops/.ssh /tmp", "H8 cp of the ssh dir"),
    (DENY, "cat /home/ops/.config/sops/*", "H8 glob over the age key dir"),

    # H7: raw device writes that are not dd
    (DENY, "cat /dev/zero > /dev/sda", "H7 redirect to device"),
    (DENY, "tee /dev/sda < /tmp/x", "H7 tee to device"),
]


# Every payload below is one the second audit fed to guard.evaluate() and got
# ALLOW for, while the command violates a hard rule. v2 turned each into a
# contract. The remote block matters most: `tsh ssh` is the only sanctioned way
# to reach another host, so it is exactly where a destructive command shows up,
# and v1 never looked past the `tsh` token.
REMOTE = [
    # R1: the remote command argument of tsh ssh / btsh
    (DENY, 'tsh ssh ops-agent@workstation-a "rm -rf /mnt/media/Movies"', "R1 remote media delete"),
    (DENY, "tsh ssh ops-agent@hv-1 'sudo wipefs -a /dev/sda'", "R1 remote wipefs"),
    (DENY, 'tsh ssh ops-agent@workstation-b "ssh root@workstation-a ls"', "R1 plain ssh nested inside tsh"),
    (DENY, "btsh ssh ops-agent@console 'mkfs.ext4 /dev/sdb1'", "R1 btsh remote mkfs"),
    (DENY, "tsh ssh ops-agent@hv-1 -- rm -rf /home/ops", "R1 remote after -- separator"),
    (DENY, 'tsh ssh --tty ops-agent@workstation-a "dd if=/tmp/x of=/dev/sdb"', "R1 remote dd behind a tsh flag"),
    (DENY, "tsh ssh -l ops-agent workstation-b 'rm -rf /mnt/media'", "R1 tsh -l with separated value"),
    (ALLOW, "tsh ssh ops-agent@workstation-b uptime", "R1 remote read command"),
    (ALLOW, "tsh ssh ops-agent@hv-1 'docker ps'", "R1 remote docker ps"),
    (ALLOW, "tsh ssh ops-agent@workstation-a 'cat /etc/fstab'", "R1 remote read of a config file"),
    (ALLOW, "tsh scp /tmp/x ops-agent@hv-1:/srv/agents-data/x", "R1 tsh scp still allowed"),
    (ALLOW, "tsh status", "R1 tsh status"),
    (ALLOW, "tsh ls", "R1 tsh ls"),
    (ALLOW, "tsh ssh ops-agent@workstation-b", "R1 interactive session, no remote command"),

    # R2: dispatchers that hid the payload from argv[0]
    (DENY, 'env -S "ssh ops-agent@workstation-b ls"', "R2 env -S"),
    (DENY, 'env --split-string="mkfs.ext4 /dev/sdb1"', "R2 env --split-string="),
    (DENY, "CMD=ssh; $CMD ops-agent@workstation-b ls", "R2 variable in command position"),
    (DENY, "python3 -c \"import os; os.system('rm -rf /mnt/media')\"", "R2 python3 -c dispatch"),
    (DENY, "busybox rm -rf /", "R2 busybox applet"),
    (DENY, 'busybox sh -c "ssh workstation-a ls"', "R2 busybox shell"),
    (DENY, "/usr/bin/time ssh ops-agent@workstation-b ls", "R2 /usr/bin/time wrapper"),
    (DENY, "cd /mnt/media && rm -rf .", "R2 cd then relative delete"),
    (DENY, "cd /mnt/media/Movies && rm -f x.mkv", "R2 cd then named delete"),
    (DENY, "cp --target-directory=/mnt/media /tmp/a.mkv", "R2 cp --target-directory="),
    (DENY, "cp -t /mnt/media /tmp/a.mkv", "R2 cp -t"),
    (ALLOW, "python3 -c 'print(1)'", "R2 harmless python3 -c"),
    (ALLOW, "cd /tmp && rm -rf scratch", "R2 cd then delete outside a protected root"),
    (ALLOW, "env FOO=bar docker ps", "R2 env with an assignment"),
    (ALLOW, "cd /home/ops/.agents/skills/adapt && cat SKILL.md", "R2 cd then relative skill read"),

    # R3: the live container-907 incident, and the probe shape that hid it
    (DENY, 'tsh ssh ops-agent@hv-1 "sudo pct start 907 2>/dev/null; true"', "R3 the container-907 incident, replayed"),
    (DENY, "sudo pct stop 910", "R3 pct stop"),
    (DENY, "pct destroy 907", "R3 pct destroy"),
    (DENY, "qm set 902 --memory 4096", "R3 qm set"),
    (DENY, "tsh ssh ops-agent@hv-1 'pct set 907 --net0 name=eth0'", "R3 remote pct set"),
    (DENY, "docker ps 2>/dev/null; true", "R3 forced-success probe"),
    (DENY, "curl -s http://192.0.2.10:8099/health 2>/dev/null || true", "R3 forced-success with ||"),
    (ALLOW, "pct config 907", "R3 pct config"),
    (ALLOW, "pct list", "R3 pct list"),
    (ALLOW, "qm list", "R3 qm list"),
    (ALLOW, "qm status 902", "R3 qm status"),
    (ALLOW, "tsh ssh ops-agent@hv-1 'pct config 907'", "R3 remote pct config"),
    (ALLOW, "docker ps 2>/dev/null", "R3 stderr suppression alone"),
    (ALLOW, "grep -q foo /tmp/x || true", "R3 forced success alone"),

    # R4: found by probing the v2 matcher itself, not by the audit. The first
    # one is the same class of bug as v1's `timeout 30`: tsh joins its remaining
    # argv with spaces, so `bash -c 'rm -rf /x'` arrives flattened and the
    # payload stops being an argument to anything.
    (DENY, "tsh ssh ops-agent@workstation-a bash -c 'rm -rf /mnt/media'", "R4 quoted payload behind a remote shell"),
    (DENY, "tsh ssh ops-agent@workstation-a rm -rf /mnt/media", "R4 unquoted remote delete"),
    (DENY, "tsh --proxy teleport.example.com:443 ssh ops-agent@workstation-a 'wipefs -a /dev/sda'", "R4 global tsh flag before the subcommand"),
    (DENY, "timeout 30 tsh ssh ops-agent@workstation-a 'wipefs -a /dev/sda'", "R4 wrapper plus remote"),
    (DENY, "echo \"$(tsh ssh ops-agent@workstation-a 'wipefs -a /dev/sda')\"", "R4 remote inside a double-quoted substitution"),
    (DENY, "cd /mnt && cd media && rm -rf .", "R4 two cd hops into a protected root"),
    (DENY, "perl -e 'system(\"rm -rf /mnt/media\")'", "R4 perl -e dispatch"),
    (DENY, "busybox timeout 5 ssh workstation-a ls", "R4 busybox wrapping a wrapper"),
    (ALLOW, "tsh ssh ops-agent@hv-1 'pct config 907 | grep net0'", "R4 remote read with a pipe"),
    (ALLOW, "tsh ssh ops-agent@hv-1 'docker logs traefik --tail 50'", "R4 remote docker logs"),
    (ALLOW, 'git commit -m "fix: stop the pct start loop"', "R4 a commit message that names a blocked verb"),
    (ALLOW, "grep -rn 'pct start' /mnt/lab/knowledge", "R4 grepping for a blocked verb"),
]


# Fed to the guard with a policy path that does not exist. The built-in
# FALLBACK_POLICY in guard.py must carry the hard rules, and only those:
# denying everything here would brick the harness on a typo in policy.json.
FALLBACK = [
    (DENY, "ssh ops-agent@workstation-b uptime", "FB plain ssh"),
    (DENY, "sudo wipefs -a /dev/sda", "FB wipefs"),
    (DENY, "rm -rf /mnt/media/Movies/x.mkv", "FB media delete"),
    (DENY, "cat /var/lib/secret-broker/secrets/mcp.header", "FB secret read"),
    (DENY, "rm -rf /", "FB rm -rf root"),
    (DENY, 'tsh ssh ops-agent@workstation-a "rm -rf /mnt/media"', "FB remote media delete"),
    (DENY, "sudo pct start 907", "FB pct start"),
    (ALLOW, "git status --short", "FB ordinary work still runs"),
    (ALLOW, "docker ps", "FB docker ps still runs"),
    (ALLOW, "tsh ssh ops-agent@workstation-b uptime", "FB remote read still runs"),
]


def run(command, mode="pretooluse", policy=POLICY):
    payload = {"tool_name": "Bash", "tool_input": {"command": command}, "hook_event_name": "PreToolUse"}
    argv = [sys.executable, GUARD, mode]
    if policy is not None:
        argv += ["--policy", policy]
    # HARNESS_GUARD_POLICY used to select the policy. It was removed: an
    # environment variable that redirects the guard at its own policy is a
    # bypass, not a test seam. Tests pass --policy on argv instead, which the
    # root-owned hook command line never carries. It is set here, to a path
    # that does not exist, only to prove it is now inert.
    env = dict(os.environ, HOME=TEST_HOME,
               HARNESS_GUARD_POLICY="/nonexistent/should-be-ignored.json")
    return subprocess.run(
        argv,
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=env,
    )


def check(cases, label, policy=POLICY):
    failures = []
    for expect, command, name in cases:
        proc = run(command, policy=policy)
        got = DENY if proc.returncode == 2 else ALLOW
        if got != expect:
            failures.append((name, command, expect, got, proc.stderr.strip()[:140]))
    print("%-8s %s %d/%d" % (label, "FAIL" if failures else "PASS",
                             len(cases) - len(failures), len(cases)))
    for name, command, expect, got, err in failures:
        print("   [%s] %s\n      expected=%s got=%s %s" % (name, command, expect, got, err))
    return failures


def main():
    failures = check(RULES, "RULES")
    failures += check(MATCHER, "MATCHER")
    failures += check(REMOTE, "REMOTE")
    failures += check(FALLBACK, "FALLBACK", policy="/nonexistent/policy.json")

    proc = run("ssh workstation-a ls", mode="permissionrequest")
    try:
        decision = json.loads(proc.stdout)["hookSpecificOutput"]["decision"]["behavior"]
    except Exception:
        decision = "<unparseable: %r>" % proc.stdout[:120]
    if decision != "deny" or proc.returncode != 0:
        failures.append(("permissionrequest schema", "ssh workstation-a ls", "deny/exit0",
                         "%s/exit%d" % (decision, proc.returncode), proc.stderr.strip()[:140]))
        print("SCHEMA   FAIL")
    else:
        print("SCHEMA   PASS 1/1")

    # --- fallback drift -------------------------------------------------
    # FALLBACK_POLICY is a hand-copied subset of policy.json. A rule that exists
    # only in the fallback is a rule nobody maintains, so pin the direction:
    # every fallback id must still be a real rule in policy.json.
    sys.path.insert(0, HERE)
    import guard  # noqa: E402
    live_ids = {r["id"] for r in json.load(open(POLICY))["rules"]}
    fb_ids = {r["id"] for r in guard.FALLBACK_POLICY["rules"]}
    orphans = sorted(fb_ids - live_ids)
    if orphans:
        failures.append(("fallback drift", ", ".join(orphans), "subset of policy.json",
                         "orphaned ids", ""))
        print("DRIFT    FAIL: fallback ids missing from policy.json: %s" % ", ".join(orphans))
    else:
        print("DRIFT    PASS 1/1")

    total = len(RULES) + len(MATCHER) + len(REMOTE) + len(FALLBACK) + 2
    print("\n%s %d/%d guard cases" % ("FAIL" if failures else "PASS", total - len(failures), total))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
