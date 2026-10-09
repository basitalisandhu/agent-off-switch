# Threat model

## What is being protected

An AI agent acts through an identity: an Entra app registration, service principal, managed identity or agent identity; an AWS IAM role or access key; a GitHub App installation or deploy key; or a key held by an MCP connector. Whatever the agent can be talked into doing, it can only do with that identity's grants. aos is about those identities: knowing they exist, who answers for them, how far they reach, and how to stop one quickly.

## Threats aos helps with

| Threat | How it shows up | What aos does |
|---|---|---|
| Nobody knows the agent exists | an app registration or role created for a pilot and never recorded | `inventory` lists every non-human identity across Entra, AWS, GitHub and the register, and marks the ones that look like agents |
| Nobody answers for it | the creator left; no owner in Entra, no owner tag, no register row | `no-owner` flag and finding (AOS006), ranked by what the identity can reach |
| It can reach far more than its task needs | tenant-wide `Mail.ReadWrite`, `Action: "*"`, a GitHub App with admin on every repository, a directory admin role | blast-radius scoring and findings AOS001 to AOS004, AOS010 to AOS012, each with the fix |
| Its credential outlives its purpose | a client secret or access key older than 90 days, a credential nobody has used for months | `stale-credential`, `unused` and `never-used` flags (AOS007, AOS008) |
| Something new appears between reviews | a new agent identity, a new grant, an owner removed | `drift` compares two inventories and fails CI until a person accepts the change |
| It misbehaves and must be stopped now | a prompt-injected agent sending mail, a coding agent pushing to protected branches | `off` prints the ordered runbook: disable, revoke sessions and grants, delete credentials, remove role assignments, then verify in the audit log |

## Mapping to the OWASP Top 10 for Agentic Applications

Source: OWASP GenAI Security Project, [OWASP Top 10 for Agentic Applications for 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), published 9 December 2025. The names below are as listed in the project's [announcement](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/).

| Risk | Relevance to aos | aos control |
|---|---|---|
| ASI01 Agent Goal Hijack | A hijacked agent acts with whatever its identity holds. aos does not detect the hijack. | Limits the damage: findings shrink the grants; `off` stops the identity |
| ASI02 Tool Misuse | Tools reach data through the agent's identity and connectors. | Blast-radius findings on the grants behind the tools; register rows for MCP connectors |
| ASI03 Identity & Privilege Abuse | The core of aos: over-privileged, ownerless, long-lived agent identities. | `inventory`, `review` (all rules), `drift` |
| ASI04 Agentic Supply Chain Vulnerabilities | Third-party GitHub Apps, enterprise applications and MCP connectors carry their own grants. | Inventory of installations, enterprise apps and connectors with their reach; `drift` on new ones |
| ASI05 Unexpected Code Execution | Code an agent runs uses the role or key in its environment. | Findings on the runtime role (for example a CI role with `*`); `off` for the role |
| ASI06 Memory & Context Poisoning | Not addressed. | None |
| ASI07 Insecure Inter-Agent Communication | Not addressed directly. | Ownership and reach of each agent's identity only |
| ASI08 Cascading Failures | An identity that can grant itself more access turns one failure into many. | Escalation-capable grants score 90 to 100 and rank first |
| ASI09 Human-Agent Trust Exploitation | Not addressed. | None |
| ASI10 Rogue Agents | An agent identity acting outside its purpose needs to be stopped and its access proven gone. | `off` runbook with a verification command for every step, ending in the audit log |

## Microsoft's agent identity guidance

Microsoft Entra Agent ID ([What is Microsoft Entra Agent ID?](https://learn.microsoft.com/en-us/entra/agent-id/what-is-microsoft-entra-agent-id)) gives agents their own identity type, built from agent identity blueprints, with Conditional Access, Identity Protection, identity governance and sign-in and audit logs extended to agents ([identity governance for agents](https://learn.microsoft.com/en-us/entra/id-governance/agent-id-governance-overview)). aos works alongside it:

- Agent identities and blueprints in the Graph exports are read as agents (`entra-agent-identity`), and their sponsors count as owners.
- Many agents still run as ordinary app registrations, managed identities, AWS roles and GitHub Apps that Agent ID does not cover; aos puts them in the same table.
- aos is offline and needs no licence beyond the read access to take the exports.

## What aos does not protect against

- It reads exports; it does not watch in real time. An identity created after the export is invisible until the next run.
- It does not see inside an agent: prompts, tool calls, memory or model behaviour.
- It does not read Azure role assignments, AWS permission boundaries, service control policies or resource policies (see [scoring.md](scoring.md)).
- It does not prove that an agent is safe; a clean review means none of the rules matched.

## The tool's own attack surface

- **Inputs are data.** Display names, tags and register text are printed, never executed or used as paths. A display name cannot change a score; scores come from permission names, policy documents and fixed lists.
- **No network, no processes.** The package imports no network or subprocess module (a test checks this). It reads the folder you name and writes to standard output or the `--out` path.
- **No secrets.** Graph and IAM exports do not contain secret values. Key ids are shown by their last four characters; `off` prints a placeholder where the full key id is needed and the verification command that lists it.
- **Commands are printed, not run.** `off` output is for a person to read. Check every value in angle brackets before running a step.
- **Outputs are sensitive.** Inventories and SARIF files list identities, owners and grants. Treat them like the exports: keep them in private repositories and artefacts.
