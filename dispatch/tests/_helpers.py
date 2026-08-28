"""Shared helpers for the dispatch suite. Not a test module — pytest's
collection patterns (test_*.py, *_test.py) skip it."""

import json
import re


def make_kpi_runner(export, calls=None, returncode=0):
    """A runner fake for the 5gcap subprocess seam: writes the canned export
    to the --json path named in the command and returns the exit code."""
    def fake(cmd, **kw):
        if calls is not None:
            calls.append(cmd)
        m = re.search(r"--json (\S+)", cmd)
        assert m, "run_analyze must pass --json <path>"
        with open(m.group(1), "w") as f:
            json.dump(export, f)
        return returncode

    return fake
