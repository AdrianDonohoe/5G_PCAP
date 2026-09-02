# The platform is renamed NetCortex; internal project and package names are unchanged

On 2026-09-02 the repo was renamed from 5G_PCAP to **NetCortex** — "An Agentic AI Platform for Autonomous Network Operations" — with three further projects planned as sibling directories (a Change Impact Agent, a Cross-Domain Incident Correlation project, and a Digital Twin). The open question was how far the rename reaches: does it extend into the code, renaming the `5gcap`/`fivegcap` package, its directory, and the CI working-directory, or does it stop at the outward identity? We chose outward-only.

## Status

accepted

## Considered Options

- **Code-level rename** (package, directory, imports, CI): one honest name everywhere, but it is purely mechanical churn across imports, tests, CI steps, and every ADR that cites the package — no behavioral gain — and it would detach the code from the historical references in published material. Rejected.
- **Outward-only rename (chosen)**: the platform brand, repo, and docs become NetCortex; the analyzer project keeps its name. `5gcap` reads as "the 5G pcap analyzer" — a project within NetCortex, exactly as `dispatch` and `triage` already are.

## Consequences

- **The platform is NetCortex; `5gcap` is a project in it.** README, CONTEXT-MAP, and dispatch's user-visible strings name the platform; the package, its directory, `pyproject` name, and CI `working-directory` remain `5gcap`. Future projects land as sibling top-level directories.
- **Historical snapshots are not rewritten.** The published article copy, the LinkedIn post, the article diagrams, the sample Incident Record, and all prior ADRs still say 5G_PCAP — they are records of what was published at the time.
- **Old links keep working.** GitHub 301-redirects the old repo URL and `raw.githubusercontent.com` URLs, so the Medium article's image and links resolve without edits (verified 301 and 200 after the rename). The article's text still says 5G_PCAP; updating it is a separate editorial decision.
- If a code-level rename is ever wanted, it is its own mechanical ticket — this decision only declines doing it as part of the rebrand.
