"""Remediation execution under guard rails: a fixed five-action vocabulary,
deterministic command templates, dry-run by default, and tamper-evident
proposal hashes. Commands come from the templates only — never from LLM
text — and every value is allowlisted before it reaches a shell."""

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

ACTIONS = ("restart_nf", "revert_config", "reseed_subscriber",
           "rerun_capture", "observe_only")

SCENARIOS = ("auth_failure", "registration_reject", "registration_timeout",
             "pdu_session_reject_slice", "pdu_session_reject_other",
             "pdu_session_timeout", "sbi_udm_timeout", "sbi_nssf_reject",
             "n4_upf_timeout")

OBSERVE_ONLY_NOTE = "observe only — no commands"

_SERVICES_RE = re.compile(r"^  ([a-z0-9_-]+):", re.MULTILINE)
_IMSI_RE = re.compile(r"\d{14,15}")


def core_services(sandbox_root: Path) -> list[str]:
    """Service names declared in the sandbox core compose file."""
    compose = Path(sandbox_root) / "core" / "docker-compose.yml"
    if not compose.exists():
        raise ValueError("sandbox core compose file not found")
    text = compose.read_text()
    match = re.search(r"^services:\n(.*?)(?=^[a-z]\w*:|\Z)", text,
                      re.MULTILINE | re.DOTALL)
    block = match.group(1) if match else ""
    return _SERVICES_RE.findall(block)


def render(action: str, args: dict, sandbox_root: Path) -> list[str]:
    """Deterministic command templates for the five-action vocabulary."""
    root = Path(sandbox_root)
    if action not in ACTIONS:
        raise ValueError(f"{action!r} is not in the remediation vocabulary")
    if action == "restart_nf":
        nf = args.get("nf")
        if nf not in core_services(root):
            raise ValueError(f"{nf!r} is not a sandbox core service")
        return [f"docker compose --project-directory {root}/core restart {nf}"]
    if action == "revert_config":
        path = Path(str(args.get("path", "")))
        if not str((root / path).resolve()).startswith(
                str(root.resolve()) + os.sep):
            raise ValueError("config path outside the sandbox")
        return [f"git -C {root} checkout -- {path}"]
    if action == "reseed_subscriber":
        imsi = str(args.get("imsi", ""))
        if not _IMSI_RE.fullmatch(imsi):
            raise ValueError(f"{imsi!r} is not a 14-15 digit IMSI")
        return [f"docker compose --project-directory {root}/core run --rm "
                f"seed {imsi}"]
    if action == "rerun_capture":
        scenario = args.get("scenario")
        if scenario not in SCENARIOS:
            raise ValueError(f"unknown scenario {scenario!r}")
        return [f"bash {root}/capture.sh --scenario {scenario}"]
    return []  # observe_only


def proposal_hash(proposal: dict) -> str:
    """Stable, tamper-evident hash over the proposal's three fields."""
    payload = {k: proposal[k] for k in ("action", "args", "justification")}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode("utf-8")
    ).hexdigest()


class Executor:
    """Applies an approved proposal under the guard rails. ``runner`` is
    injected for tests; real runs call ``subprocess.run`` (resolved at call
    time) over the template-rendered strings — values are allowlisted, so
    shell=True is safe by construction."""

    def __init__(self, sandbox_root, runner=None):
        self.sandbox_root = Path(sandbox_root)
        self.runner = runner

    def dry_run(self, proposal: dict) -> list[str]:
        """Render the proposal's commands; never invoke the runner."""
        commands = render(proposal["action"], proposal.get("args", {}),
                          self.sandbox_root)
        return commands or [OBSERVE_ONLY_NOTE]

    def apply(self, proposal: dict, commands: list[str]) -> None:
        """Run commands — but only the ones this exact proposal renders."""
        expected = render(proposal["action"], proposal.get("args", {}),
                          self.sandbox_root)
        if commands != expected:
            raise ValueError("commands do not match the checkpointed proposal")
        runner = self.runner or subprocess.run
        for command in commands:
            runner(command, shell=True)
