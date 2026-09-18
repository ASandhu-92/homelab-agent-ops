#!/usr/bin/env python3
"""Unit tests for context-bracket.py.  Run:  python3 hooks/test_context_bracket.py"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("context-bracket.py")
SPEC = importlib.util.spec_from_file_location("context_bracket", MODULE_PATH)
context_bracket = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(context_bracket)


class BracketTests(unittest.TestCase):
    def test_percent_boundaries(self):
        cases = (
            (None, "FRESH"),
            (30, "FRESH"),
            (29, "ECONOMY"),
            (16, "ECONOMY"),
            (15, "LOW"),
            (10, "LOW"),
            (9, "HANDOFF"),
        )
        for pct, expected in cases:
            with self.subTest(pct=pct):
                self.assertEqual(context_bracket.bracket(pct), expected)

    def test_absolute_token_boundaries(self):
        cases = (
            (None, "NONE"),
            (119999, "NONE"),
            (120000, "ADVISORY"),
            (149999, "ADVISORY"),
            (150000, "LOUD"),
        )
        for latest, expected in cases:
            with self.subTest(latest=latest):
                self.assertEqual(context_bracket.absolute_bracket(latest), expected)

    def test_window_for_model(self):
        self.assertEqual(context_bracket._window_for_model("opus[1m]"), 1_000_000)
        self.assertEqual(context_bracket._window_for_model("claude-fable-5-1"), 1_000_000)
        self.assertIsNone(context_bracket._window_for_model("claude-opus-4-8"))
        self.assertIsNone(context_bracket._window_for_model(None))


class EndToEndTests(unittest.TestCase):
    """Run the hook as Claude Code would: a payload on stdin, a transcript on
    disk under a fake HOME. The nudge must appear on the first crossing and
    stay silent on the next identical prompt."""

    def _run(self, home, payload):
        env = dict(os.environ, HOME=home)
        return subprocess.run([sys.executable, str(MODULE_PATH)], input=json.dumps(payload),
                              capture_output=True, text=True, env=env, timeout=20)

    def test_nudge_fires_once_per_transition(self):
        with tempfile.TemporaryDirectory() as home:
            cwd = "/work/project"
            sid = "session-1"
            project_dir = Path(home) / ".claude" / "projects" / "-work-project"
            project_dir.mkdir(parents=True)
            # 170k of a 200k window: 15% left -> LOW, and over the 150k absolute rule.
            usage = {"message": {"model": "claude-opus-4-8",
                                 "usage": {"input_tokens": 1000, "cache_read_input_tokens": 169000,
                                           "cache_creation_input_tokens": 0}}}
            (project_dir / f"{sid}.jsonl").write_text(json.dumps(usage) + "\n")
            payload = {"session_id": sid, "cwd": cwd}

            first = self._run(home, payload)
            self.assertEqual(first.returncode, 0)
            out = json.loads(first.stdout)["hookSpecificOutput"]["additionalContext"]
            self.assertIn("[LOW]", out)
            self.assertIn("[ABS-LOUD]", out)

            second = self._run(home, payload)
            self.assertEqual(second.returncode, 0)
            self.assertEqual(second.stdout, "", "steady state must inject nothing")

    def test_missing_transcript_is_silent(self):
        with tempfile.TemporaryDirectory() as home:
            r = self._run(home, {"session_id": "nope", "cwd": "/nowhere"})
            self.assertEqual(r.returncode, 0)
            self.assertEqual(r.stdout, "")


if __name__ == "__main__":
    unittest.main()
