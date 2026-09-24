# Incident Response Playbooks

![Format](https://img.shields.io/badge/format-Markdown-blue) ![Diagrams](https://img.shields.io/badge/diagrams-Mermaid-orange) ![Framework](https://img.shields.io/badge/mapped_to-MITRE_ATT%26CK-red) ![Lifecycle](https://img.shields.io/badge/lifecycle-NIST_SP_800--61-lightgrey)

A set of five self-contained incident response playbooks, each covering a different attack surface — identity/lateral movement, network edge (WAF/DDoS), cloud posture, AI/LLM systems, and third-party/supply-chain risk. Every playbook follows the same structure, so the format becomes familiar quickly and the differences that matter are the ones in the content, not the layout.

Each file includes a realistic trigger scenario, a MITRE ATT&CK (or ATLAS, for the AI scenario) mapping, detection queries, a decision-branch communication flow, a RACI table, and a short design-notes FAQ explaining the reasoning behind non-obvious calls (e.g., when to auto-remediate vs. require human approval).

## Playbooks

| # | Playbook | Domain | Primary Reference |
|---|---|---|---|
| 01 | [Credential Theft → Ransomware](./01-credential-theft-ransomware.md) | Identity / Active Directory / EDR | MITRE ATT&CK — T1558.003 (Kerberoasting) |
| 02 | [WAF/DDoS Data-Integrity Attack](./02-waf-ddos-data-integrity.md) | Network edge / application security | MITRE ATT&CK — T1498, T1190 |
| 03 | [CSPM Cloud Storage Exposure](./03-cspm-cloud-exposure.md) | Cloud security posture | MITRE ATT&CK (Cloud) — T1530 |
| 04 | [AI Governance: Prompt Injection](./04-ai-governance-prompt-injection.md) | AI/LLM systems | MITRE ATLAS — AML.T0051 |
| 05 | [TPRM: Third-Party Data-Partner Compromise](./05-tprm-supply-chain.md) | Vendor / supply-chain risk | MITRE ATT&CK — T1199, T1195.002 |

## Methodology

Every playbook is structured around the same seven stages:

1. **Purpose and Scope** — what the playbook covers, explicitly, and what it doesn't.
2. **Risk Assessment** — assets, threat actors, vulnerabilities, impact.
3. **Policies and Procedures** — detect → classify → respond → communicate → review.
4. **Roles and Responsibilities** — a RACI model and an escalation path.
5. **Incident Response Plan** — mapped to the NIST SP 800-61 four-phase lifecycle (Preparation → Detection & Analysis → Containment/Eradication/Recovery → Post-Incident Activity).
6. **Train and Educate** — a tabletop exercise design specific to the scenario.
7. **Continuous Improvement** — a feedback loop from real incidents back into detection tuning and playbook updates.

Each playbook opens with a concrete trigger scenario rather than staying abstract, because a playbook that's never been run against a specific case tends to read as generic guidance rather than something a team could actually execute under pressure.

## Design Patterns Across the Set

A few decisions repeat across playbooks on purpose:

- **Policy-as-code gating.** Playbooks 01, 03, and 04 all route high-impact actions through an explicit `ALLOW` / `REQUIRE_APPROVAL` / `BLOCK` decision rather than either full automation or fully manual response. The dividing line is consistent: automate what's low-risk and reversible (reverting a cloud config), require a human for what's high-impact and hard to undo (disabling an account, isolating a host, executing a bulk data export).
- **The "unmanaged inventory" failure mode.** Playbook 04's "shadow AI" (a new AI feature shipped without security review) and Playbook 05's "partner integration nobody remembered was active" are the same underlying problem in two different domains — you can't govern or monitor what you don't know exists.
- **Data integrity as a first-class question.** Playbooks 02 and 05 both treat "was the underlying data corrupted" as a question equally important as "was there unauthorized access" — availability and access aren't the only things worth protecting.

This same guardrail architecture — evidence boundaries, explainable risk scoring, human-in-the-loop approval, tamper-evident audit logging — is implemented as working code in a companion project: [SOC-Incident-Orchestrator](https://github.com/CdxDebian/SOC-Incident-Orchestrator).

## Repository Structure

```
.
├── README.md
└── playbooks/
    ├── 01-credential-theft-ransomware.md
    ├── 02-waf-ddos-data-integrity.md
    ├── 03-cspm-cloud-exposure.md
    ├── 04-ai-governance-prompt-injection.md
    └── 05-tprm-supply-chain.md
```

## Notes on the scenarios

The organizations and incidents described are illustrative composites, not real reported breaches. Detection queries (KQL/SQL) and guardrail logic (Python) are written to be realistic and directly adaptable, not copy-paste production code — field names, table names, and thresholds should be adjusted to match a real environment before use.

---

**Author:** Rahul Shrivastava — Cybersecurity / SOC Analyst
[Website](https://www.rahulshrivastava.co.in) · [LinkedIn](https://linkedin.com/in/shriv-rahul) · [GitHub](https://github.com/CdxDebian)
