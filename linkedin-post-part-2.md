# LinkedIn post — After the Root Cause, the Action

Companion post for the Medium article (`after-the-root-cause-the-action.md`).
Replace `[paste Medium article URL]` with the published link before posting.

---

**After the root cause, the action.**

My triage agent could explain *why* a 5G session failed — every citation checked against the pcap. But an explanation is not a fix. Someone still had to decide what to do. So I built dispatch, the second project in NetCortex: the half where the agent proposes and a human disposes.

🚦 Nothing executes without human approval. The pipeline stops at a gate, the record ends **pending**, the process exits.

How it flows:
- An Alarm event is raised by a human or synthesized by detect-kpi (5gcap KPIs vs a golden baseline)
- Three specialist agents gather evidence — PCAP, logs, KPIs — each bound by a contract: say only what your source proves
- Correlation joins findings by strict equality. No similarity scores, no guessing a join
- Triage's LATS search (imported as a library, not rewritten) finds the root cause
- The proposer picks from a fixed vocabulary of five actions; commands are template-rendered, never LLM text
- The record is hashed — tamper with it and it refuses to execute

On a real n4_upf_timeout run it detected the degradation itself, found thirteen NAS cause-38 rejects, proposed `restart_nf smf` — and stopped. Execution log empty. Waiting for a human.

The full write-up → [paste Medium article URL]
Code is public: github.com/AdrianDonohoe/NetCortex

#5G #AI #AgenticAI #Telecom #Observability #NetCortex
