"""CLI contract tests: the --help surface reserves the four subcommands."""

import pytest

from dispatch.cli import main


def test_help_lists_reserved_subcommands(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for cmd in ("handle", "detect-kpi", "approve", "reject"):
        assert cmd in out
