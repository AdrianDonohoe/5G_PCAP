# LinkedIn post — The LLM Proposes, the Code Disposes

Companion post for the Medium article (`the-llm-proposes-the-code-disposes.md`).
Replace `[paste Medium article URL]` with the published link before posting.

---

**The LLM proposes, the code disposes.**

I've spent too many hours in Wireshark finding *where* a 5G attach failed — then explaining *why*. LLMs are great at the "why"… and great at inventing evidence. So I built a triage agent where that's structurally impossible.

📡 Every citation the model makes is checked against the packet capture — message, timestamp (±0.5 ms), cause code. A hallucinated citation gets rejected mechanically, not "caught by prompt".

It works like this:
- A deterministic decoder turns the pcap into flows, procedures, KPIs
- A failure-injection lab (Open5GS + UERANSIM) generates six labeled failure scenarios
- A LATS tree-search agent investigates each failure, grounding every claim in decoded messages
- A separate judge model scores the result — a model grading its own output is a rubber stamp

On a real lab capture with a wrong-Ki auth failure, it cited two messages, grounded both, and was judged 4 × 1.0.

The full write-up → [paste Medium article URL]
Code is public: github.com/AdrianDonohoe/5G_PCAP

#5G #AI #AgenticAI #Telecom #Observability
