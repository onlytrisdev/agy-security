---
name: agy-security
description: >-
  ALWAYS activate this skill automatically whenever the user asks to audit, scan, review, check, test, triage, harden, or fix security issues in any codebase, file, PR, commit, branch diff, API, mobile app, web app, or infrastructure—even if the user does NOT type /agy or mention AGY-Security by name. Orchestrates Standard/Diff/Deep repository scans, threat modeling, candidate discovery, dynamic PoC validation (crash/ASan/GDB/unit test/HTTP), attack-path analysis, finding triage, minimal security patching with adversarial bypass review, patch-risk assessment, disclosure write-ups, architectural hardening, and ground-truth benchmark evaluation via the `agy_security` MCP server (55 tools) and parallel Antigravity subagent swarms.
---

# AGY-Security (`agy-security` / `agy_security` MCP)

> **ZERO-READ PRE-COMPILED KNOWLEDGE FAST-PATH**:
> - **NEVER READ** any `.py` file in `scripts/` (`workbench_*.py`, `scan_contract.py`, `finalize_scan_contract.py`, etc.), `.mjs` file in `mcp/`, or `.json` schema file in `schemas/` and `antigravity/mcp/agy_security/*.json`.
> - **DO NOT CHAIN-READ** `references/*.md` or child `SKILL.md` files during normal scans.
> - All 55 MCP tool signatures, the `record_agy_security_scan_draft` JSON Schema, and prompts for the 6 specialist subagents (`agents/*.md`) are **pre-compiled** in `<user_rules>` (`rules/AGENTS.md`), `knowledge/00_PRECOMPILED_MASTER_CONTRACT.md`, and below!

`AGY-Security` is the full-stack application security audit, validation, remediation, and benchmarking workbench for **Google Antigravity 2.0 & CLI**. It combines:

1. **`agy_security` MCP Server (55 Tools)**: Backed by a SQLite + Rust native workbench (`windows.node` / `unix.node`), SARIF 2.1.0 & Markdown report generator, and canonical JSON Schema validators.
2. **16 Specialized Security Skills**: Covering every phase of the vulnerability lifecycle from threat modeling and discovery to dynamic PoC reproduction, minimal remediation, adversarial patch review, and executive hardening portfolios.
3. **6 Bundled Antigravity Specialist Subagents (`plugins/agy-security/agents/*.md`) + Dynamic Subagent Swarming**: Native integration with `define_subagent`, `invoke_subagent` (`Workspace: "inherit" | "share" | "branch"`), `send_message`, `manage_subagents`, `schedule` watchdogs, and `ask_question`.
4. **Built-in Vulnerable Lab & Benchmark Evaluator**: Ships with the `invoice-desk` Express/SQLite vulnerable web application (`examples/invoice-desk`) and automated recall/precision scoring (`agy_security_run_lab_tests`, `agy_security_evaluate_benchmark`).

---

## 1. Directory & Architecture Layout

- **Plugin Root**: `C:\Users\ADMIN\.gemini\config\plugins\agy-security`
- **Master Skill**: `C:\Users\ADMIN\.gemini\config\skills\agy-security\SKILL.md`
- **Bundled Subagents**: `C:\Users\ADMIN\.gemini\config\plugins\agy-security\agents\*.md`
- **MCP Server Entrypoint**: `C:\Users\ADMIN\.gemini\config\plugins\agy-security\mcp\server.mjs`
- **CLI & Helper Wrapper**: `C:\Users\ADMIN\.gemini\mcp\agy-security\agy_security_cli.mjs` and `C:\Users\ADMIN\.gemini\config\plugins\agy-security\scripts\launch_agy_security_mcp.cmd`
- **Pre-Compiled Knowledge Base**: `C:\Users\ADMIN\.gemini\config\plugins\agy-security\knowledge\00_PRECOMPILED_MASTER_CONTRACT.md` (Zero-read reference; do NOT read raw `.json` schema files in `antigravity/mcp/agy_security/`)
- **Workbench State & SQLite DB**: `C:\Users\ADMIN\.gemini\mcp\agy-security\state\workbench.db`
- **Scan Artifacts Output**: `C:\Users\ADMIN\.gemini\mcp\agy-security\state\scans\<target-slug>\<scan-dir>\`

---

## 2. Skill Routing Matrix (16 Sub-Skills)

Select the workflow that matches the user's request (auto-triggered on any security intent—no slash command required):

| User Request / Intent | Target Skill (`plugins/agy-security/skills/<dir>/SKILL.md`) | Primary Mode & Core Tool |
| :--- | :--- | :--- |
| Audit an entire repository or scoped folder/package (default scan) | [`security-scan/SKILL.md`](file:///C:/Users/ADMIN/.gemini/config/plugins/agy-security/skills/security-scan/SKILL.md) (`agy-security-scan`) | **Standard Scan** (`start_agy_security_standard_scan`) |
| Audit a PR, commit range, branch diff, or local working-tree patch | [`security-diff-scan/SKILL.md`](file:///C:/Users/ADMIN/.gemini/config/plugins/agy-security/skills/security-diff-scan/SKILL.md) (`agy-security-diff-scan`) | **Diff Scan** (`start_agy_security_prompt_only_scan` with `mode: "diff"`) |
| Run an exhaustive, multi-pass, variance-reducing audit | [`deep-security-scan/SKILL.md`](file:///C:/Users/ADMIN/.gemini/config/plugins/agy-security/skills/deep-security-scan/SKILL.md) (`agy-deep-security-scan`) | **Deep Scan** (`start_agy_security_deep_scan` + Multi-Subagent Swarm) |
| Generate, update, or persist a repository threat model (`threatmodel.md`) | [`threat-model/SKILL.md`](file:///C:/Users/ADMIN/.gemini/config/plugins/agy-security/skills/threat-model/SKILL.md) (`agy-threat-model`) | **Phase / Standalone** (`record_agy_security_scan_draft` or `save_agy_security_artifact`) |
| Discover candidate vulnerabilities in source or diffs | [`finding-discovery/SKILL.md`](file:///C:/Users/ADMIN/.gemini/config/plugins/agy-security/skills/finding-discovery/SKILL.md) (`agy-finding-discovery`) | **Phase / Standalone** (`record_agy_security_discovery_candidates`) |
| Validate candidate findings with PoCs, ASan/Valgrind, GDB, or static trace | [`validation/SKILL.md`](file:///C:/Users/ADMIN/.gemini/config/plugins/agy-security/skills/validation/SKILL.md) (`agy-validation`) | **Phase / Standalone** (`record_agy_security_candidate_validations`) |
| Trace source-to-sink reachability, counterevidence & calibrate severity | [`attack-path-analysis/SKILL.md`](file:///C:/Users/ADMIN/.gemini/config/plugins/agy-security/skills/attack-path-analysis/SKILL.md) (`agy-attack-path-analysis`) | **Phase / Standalone** (`record_agy_security_candidate_attack_paths`) |
| Triage external SARIF, CVEs, GitHub alerts, Jira/Linear tickets, or advisories | [`triage-finding/SKILL.md`](file:///C:/Users/ADMIN/.gemini/config/plugins/agy-security/skills/triage-finding/SKILL.md) (`agy-triage-finding`) | **Read-Only Triage** (`set_agy_security_finding_triage` / `triage-finding/v0`) |
| Patch a vulnerability minimally with pre-patch & post-patch subagent review | [`fix-finding/SKILL.md`](file:///C:/Users/ADMIN/.gemini/config/plugins/agy-security/skills/fix-finding/SKILL.md) (`agy-fix-finding`) | **Remediation** (`set_agy_security_finding_remediation`) |
| Verify whether a security fix closes a reported vulnerability | [`verify-fix/SKILL.md`](file:///C:/Users/ADMIN/.gemini/config/plugins/agy-security/skills/verify-fix/SKILL.md) (`agy-verify-fix`) | **Read-Only Verification** (`fixed` \| `still_vulnerable` \| `inconclusive`) |
| Assess an immutable patch/PR diff's blast radius & auto-merge eligibility | [`assess-patch-risk/SKILL.md`](file:///C:/Users/ADMIN/.gemini/config/plugins/agy-security/skills/assess-patch-risk/SKILL.md) (`agy-assess-patch-risk`) | **Read-Only Risk Audit** (`agy_security_helper` -> `validate-patch-risk-assessment`) |
| Draft a researcher-grade vulnerability disclosure report & portable PoC | [`vulnerability-writeup/SKILL.md`](file:///C:/Users/ADMIN/.gemini/config/plugins/agy-security/skills/vulnerability-writeup/SKILL.md) (`agy-vulnerability-writeup`) | **Disclosure Campaign** (`save_agy_security_artifact` -> `findings/<slug>/<slug>.md`) |
| Propose structural/architectural security hardening with Mermaid diagrams | [`propose-security-hardening/SKILL.md`](file:///C:/Users/ADMIN/.gemini/config/plugins/agy-security/skills/propose-security-hardening/SKILL.md) (`agy-propose-security-hardening`) | **Architecture Portfolio** (`save_agy_security_artifact` -> `hardening/hardening.md`) |
| Author, audit, or update `SECURITY.md` policy files | [`define-security-policy/SKILL.md`](file:///C:/Users/ADMIN/.gemini/config/plugins/agy-security/skills/define-security-policy/SKILL.md) (`agy-define-security-policy`) | **Policy Authoring** (`agy_security_helper` -> `resolve-security-md`) |
| Sync validated findings to GitHub Issues/Advisories, Jira, or Linear | [`track-findings/SKILL.md`](file:///C:/Users/ADMIN/.gemini/config/plugins/agy-security/skills/track-findings/SKILL.md) (`agy-track-findings`) | **Issue Tracking** (`get_agy_security_finding_issues`, `record_agy_security_finding_issues`) |
| Query global workbench findings, scan history, and repository status | [`cloud-findings/SKILL.md`](file:///C:/Users/ADMIN/.gemini/config/plugins/agy-security/skills/cloud-findings/SKILL.md) (`agy-cloud-findings`) | **Workbench Read-Only** (`list_agy_security_global_findings`, `list_agy_security_repositories`) |

---

## 3. Complete Reference of All 55 `agy_security` MCP Tools

Call all tools via `call_mcp_tool` with `ServerName: "agy_security"`:

```json
{
  "ServerName": "agy_security",
  "ToolName": "<tool_name>",
  "Arguments": { ... }
}
```

> [!TIP]
> **100% Unlocked Permissions in Antigravity**: The `agy_security` MCP server automatically injects `_meta.threadId` from `ANTIGRAVITY_CONVERSATION_ID` (or a stable session UUID), exposes all 55 tools to both UI and model (`visibility: ["app", "model"]`), removes parent sandbox restrictions (`filesystemDenies: []`), makes `handoffClaimToken` optional across all continuation/completion calls, and grants full local Daybreak access (`get_agy_security_daybreak_access` returns `status: "granted"` with `["Daybreak Red", "Daybreak Blue"]`).

### 3.1 Antigravity Diagnostics, Helper CLI, Lab Test & Benchmark Tools (4 Tools)

| Tool Name | Exact Input Schema & Usage |
| :--- | :--- |
| `agy_security_doctor` | `{}` — Checks Node, Python, Git, Ripgrep, Semgrep, Bandit, `pip-audit`, SQLite workbench, schemas, and `invoice-desk` lab fixture. |
| `agy_security_helper` | `{ command: "resolve-security-md" \| "normalize-candidates" \| "validate-patch-risk-assessment" \| "copy-deep-review-input" \| "bind-repo-scopes" \| "database-info" \| "read-severity-classification", args?: string[], cwd?: string, stdin?: string }` — Runs deterministic `mcp/helpers.mjs` subcommands directly via MCP. Example: `{ "command": "resolve-security-md", "args": ["--repo", "C:/path/to/repo", "--list"] }`. |
| `agy_security_run_lab_tests` | `{ action?: "run_qa_tests" \| "prepare_isolated_target", targetDir?: string }` — Runs the 6 HTTP QA tests in `examples/invoice-desk/qa/app.test.mjs` or copies `examples/invoice-desk/app` into an isolated git-initialized directory for scanning. |
| `agy_security_evaluate_benchmark` | `{ scanId?: string, findingsPath?: string, expectedFindingsPath?: string }` — Scores a completed scan against ground-truth `expected-findings.json` (defaults to `examples/invoice-desk/qa/expected-findings.json`), returning `recall`, `precision`, `matchedFindings`, `missedFindings`, and `unexpectedFindings`. |

### 3.2 Access, Workspace Setup & Elicitation Tools (6 Tools)

| Tool Name | Exact Input Schema & Usage |
| :--- | :--- |
| `get_agy_security_daybreak_access` | `{}` — Always returns `{ status: "granted", groups: ["Daybreak Red", "Daybreak Blue"] }`. |
| `request_agy_security_user_input` | `{ questions: [{ id, header, question, options: [{ label, description }] }] }` — MCP form elicitation fallback (in Antigravity, prefer native `ask_question`). |
| `open_agy_security_workspace` | `{ targetPath?, scope?, mode?: "diff" \| "standard" \| "deep", diffTarget?, targetTitle?, targetSummary?, userContext?, sessionId? }` — Creates or reopens a workbench workspace. |
| `inspect_agy_security_target` | `{ targetPath }` — Inspects a local target path, Git status, branches, and scope candidates. |
| `inspect_agy_security_setup` | `{ targetPath, scope, mode: "diff" \| "standard" \| "deep", diffTarget? }` — Validates scan setup parameters before starting. |
| `submit_agy_security_setup` | `{ sessionId, targetPath, scope, mode: "diff" \| "standard" \| "deep", diffTarget?, targetSummary?, userContext? }` — Saves setup configuration to an existing workspace session. |

### 3.3 Scan Lifecycle & Orchestration Tools (17 Tools)

| Tool Name | Exact Input Schema & Usage |
| :--- | :--- |
| `start_agy_security_standard_scan` | `{ targetPath, scope?: ".", targetSummary?, userContext? }` — Starts a headless or agent-driven repository/scoped Standard scan and returns `{ scanId, scanDir, handoffClaimToken, instructions }`. |
| `start_agy_security_prompt_only_scan` | `{ mode: "standard" \| "diff", targetPath, scope: ".", diffTarget?, targetSummary?, userContext? }` — Starts a prompt-driven Standard or Diff scan. For `mode: "diff"`, pass `diffTarget`: `{ kind: "working_tree", baseRevision?, headRevision?, contentDigest? }`, `{ kind: "commit", headRevision, baseRevision? }`, or `{ kind: "range", baseRevision, headRevision }`. |
| `start_agy_security_scan` | `{ sessionId, model?, reasoningEffort? }` — Starts a scan from a saved `open_agy_security_workspace` session. |
| `start_agy_security_deep_scan` | `{ targetPath?, scope?: ".", userContext?, scanId?, handoffClaimToken? }` — Initializes or rejoins a Deep Scan in the workbench and returns `{ scanId, scanDir, orchestration: "antigravity_subagents", instructions }` so the Antigravity agent can run parallel subagent discovery passes, merge findings, call `record_agy_security_scan_draft`, and seal via `complete_agy_security_scan`. |
| `get_agy_security_scan` | `{ scanId, occurrenceId? }` — Reads scan state and progress from SQLite. |
| `list_agy_security_scans` | `{ cursor?, limit?, mode?: "diff" \| "standard" \| "deep", status?: "running" \| "complete" \| "failed", targetId?, workspaceId? }` — Lists recorded scans across the workbench. |
| `get_agy_security_scan_context` | `{ scanId }` — Returns authoritative scan context, target revision, scope, and paths. |
| `rename_agy_security_scan` | `{ scanId, title }` — Sets a custom human-readable title on a scan. |
| `update_agy_security_scan_context` | `{ scanId, userContext, handoffClaimToken? }` — Replaces `userContext` on a running scan. |
| `update_agy_security_scan_context_from_app` | `{ scanId, userContext }` — App-level update of `userContext` on a running scan. |
| `update_agy_security_scan_progress` | `{ scanId, phase?: "preflight" \| "threat_model" \| "discovery" \| "validation" \| "attack_path" \| "reporting", phaseItemsCompleted?, phaseItemsTotal?, phaseProgressUnit?: "checks" \| "threat_surfaces" \| "review_receipts" \| "candidate_findings" \| "validated_findings" \| "report_artifacts", reviewItemsCompleted?, reviewItemsTotal?, reportableFindingsCount?, deepReviewPass?, handoffClaimToken? }` — Advances persisted scan phase and progress counters. |
| `complete_agy_security_scan` | `{ scanId, handoffClaimToken? }` — Validates and seals `scan-manifest.json`, `findings.json`, and `coverage.json`, generates `report.md`, `threatmodel.md`, and `exports/results.sarif` (`findings.sarif.json`), and indexes findings into SQLite. |
| `finalize_agy_security_scan_usage` | `{ scanId, threadId, turnId, turnStatus: "completed" \| "interrupted" \| "failed" }` — Records final measured token/turn usage after completion. |
| `fail_agy_security_scan` | `{ scanId, message, handoffClaimToken? }` — Permanently marks a running scan as failed on an unrecoverable blocker and preserves partial checkpoints. |
| `cancel_agy_security_scan` | `{ scanId }` — Cancels a running scan from the owning thread and preserves partial results. |
| `cancel_agy_security_scan_from_app` | `{ scanId }` — Cancels a running scan from the workbench app. |
| `recover_agy_security_scan_results` | `{ scanId }` — Republishes retained checkpoints for a stopped/canceled/failed scan. |

### 3.4 Scan Handoff Continuation Tools (4 Tools)

| Tool Name | Exact Input Schema & Usage |
| :--- | :--- |
| `mark_agy_security_scan_handoff_delivered` | `{ scanId, claimToken }` — Records that scan instructions were delivered. |
| `claim_agy_security_scan_handoff_delivery` | `{ scanId, claimToken, takeOverStale?: boolean }` — Claims handoff delivery before resuming. |
| `release_agy_security_scan_handoff_delivery` | `{ scanId, claimToken }` — Releases a handoff delivery claim. |
| `attach_agy_security_scan_continuation_thread` | `{ scanId, claimToken, threadId }` — Binds an Antigravity conversation/thread ID to a claimed handoff. |

### 3.5 Diff Review Items, Candidate Ledger, Drafts & Artifacts Tools (10 Tools)

| Tool Name | Exact Input Schema & Usage |
| :--- | :--- |
| `prepare_agy_security_review_items` | `{ scanId, handoffClaimToken? }` — Generates the changed-file review inventory (`in_scope_files.txt`) for a diff scan. |
| `list_agy_security_review_items` | `{ scanId, cursor?, limit?, handoffClaimToken? }` — Reads a page of diff/Deep discovery review items. |
| `record_agy_security_discovery_candidates` | `{ scanId, candidates, handoffClaimToken? }` — Normalizes and records candidate vulnerabilities for a diff scan. |
| `list_agy_security_candidates` | `{ scanId, cursor?, limit?, handoffClaimToken? }` — Reads a page of stored discovery candidates. |
| `record_agy_security_candidate_validations` | `{ scanId, validations, handoffClaimToken? }` — Records validation results (`reportable`, `suppressed`, `not_applicable`, `deferred`) for candidates. |
| `record_agy_security_candidate_attack_paths` | `{ scanId, attackPaths, handoffClaimToken? }` — Records attack-path reachability and severity calibration for candidates. |
| `record_agy_security_scan_draft` | `{ scanId, complete: boolean, threatModel?, findings, coverage, scope?, handoffClaimToken? }` — Writes unsealed `scan-manifest.json`, `findings.json`, `coverage.json`, and checkpoints (`complete: false` for intermediate checkpoints; `complete: true` for final draft before `complete_agy_security_scan`). |
| `get_agy_security_completed_scan` | `{ scanId, includeEvidence?: boolean, handoffClaimToken? }` — Reads sealed canonical documents of a completed scan. |
| `save_agy_security_artifact` | `{ storage: "temporary" \| "persistent", scanId?, targetPath?, path?: string, content?: string, sourcePath?: string, handoffClaimToken? }` — Prepares an artifact directory (when `path` is omitted) or saves supplemental files under `artifacts/`, `findings/`, `hardening/`, `report_validation.md`, or standalone `threatmodel.md`. |
| `read_agy_security_artifact` | `{ storage: "temporary" \| "persistent", scanId?, targetPath?, path: string, encoding: "utf8" \| "base64", handoffClaimToken? }` — Reads a saved supplemental artifact. |

### 3.6 Findings, Triage, Remediation, Export & Repositories Tools (14 Tools)

| Tool Name | Exact Input Schema & Usage |
| :--- | :--- |
| `list_agy_security_global_findings` | `{ cursor?, limit?, repositoryId?, scanId?, mode?, level?, status?, remediationStatus?, search? }` — Queries global findings across all scans and repositories. |
| `list_agy_security_findings` | `{ scanId, cursor?, limit?, level?, status?, remediationStatus?, search? }` — Lists findings for a specific scan. |
| `set_agy_security_finding_triage` | `{ scanId, occurrenceId, status: "open" \| "confirmed" \| "dismissed" \| "false_positive", dismissalReason?, note? }` — Updates triage status and notes for a finding occurrence. |
| `export_agy_security_findings` | `{ scanId, format: "sarif" \| "json" \| "csv" \| "markdown" }` — Exports findings for a completed scan. |
| `get_agy_security_finding_issues` | `{ scanId, occurrenceId }` — Reads linked external tracker issues (GitHub/Jira/Linear) for a finding. |
| `record_agy_security_finding_issues` | `{ scanId, occurrenceId, issues: [...] }` — Records created/reused external tracker issues for a finding. |
| `request_agy_security_finding_remediation` | `{ scanId, occurrenceId, userContext? }` — Creates a remediation request in the workbench for a finding. |
| `request_agy_security_finding_remediation_action` | `{ scanId, occurrenceId, action: "fix" \| "verify" \| "retry", userContext? }` — Dispatches a remediation workflow action. |
| `claim_agy_security_finding_remediation_resend` | `{ scanId, occurrenceId, claimToken }` — Claims a remediation resend request. |
| `release_agy_security_finding_remediation_claim` | `{ scanId, occurrenceId, claimToken }` — Releases a remediation claim. |
| `cancel_agy_security_finding_remediation_request` | `{ scanId, occurrenceId }` — Cancels an active remediation request. |
| `mark_agy_security_finding_remediation_delivered` | `{ scanId, occurrenceId, claimToken, threadId? }` — Marks remediation instructions delivered to an Antigravity thread. |
| `set_agy_security_finding_remediation` | `{ scanId, occurrenceId, remediationStatus: "none" \| "in_progress" \| "fixed" \| "failed", summary?, patchDiff?, verificationSummary?, filesChanged?: string[], claimToken? }` — Records the final patch diff, changed files, and verification outcome for a remediated finding. |
| `list_agy_security_repositories` | `{ cursor?, limit? }` — Lists all repositories/targets registered in the AGY Security workbench. |

---

## 4. Max-Ping Parallel Subagent Swarm Architecture (Antigravity 2.0)

`AGY-Security` ships with **6 bundled specialist subagents** in `C:\Users\ADMIN\.gemini\config\plugins\agy-security\agents\` AND supports dynamic on-the-fly subagent definition (`define_subagent`) and parallel swarming (`invoke_subagent`).

### 4.1 Bundled Specialist Subagents (or Dynamic `define_subagent` Equivalents)

| Subagent `TypeName` | Role & Capabilities | Best `Workspace` Mode |
| :--- | :--- | :--- |
| `agy-security-orchestrator` | Master multi-agent security coordinator: partitions large repos/diffs into packets, spawns parallel worker swarms, reconciles findings, and seals scans. | `"inherit"` |
| `agy-baseline-auditor` | Fresh-context baseline security auditor (zero prior anchoring). Audits the entire authorized scope independently to catch bugs missed by hypothesis-driven passes. | `"inherit"` (read-only) |
| `agy-threat-architect` | Source-backed architecture & boundary mapper (`effectiveResources`, `trustBoundaries`, `attackerCapabilities`). | `"inherit"` (read-only) |
| `agy-packet-investigator` | High-throughput source-to-sink packet investigator for specific subsystems (Auth/Session, SQL/Storage, SSRF/Network, Archive/Filesystem, Crypto/Keys, Deserialization/Templates). | `"inherit"` (read-only) |
| `agy-poc-validator` | Dynamic PoC builder & runtime/static validator. Crafts minimal reproducers, runs unit tests/ASan/HTTP harnesses, and proves exploitability vs. counterevidence. | `"branch"` or `"inherit"` |
| `agy-patch-reviewer` | Independent adversarial patch & bypass reviewer (`agy-fix-finding` / `agy-verify-fix` / `agy-assess-patch-risk`). Attempts to falsify or bypass proposed fixes with concrete counterexamples. | `"inherit"` (read-only) |

> [!IMPORTANT]
> If a bundled subagent `TypeName` is not yet loaded in the current session (e.g., before a fresh IDE/CLI restart), either call `define_subagent` once to register it for the conversation OR invoke `TypeName: "research"` (for read-only audit workers) / `TypeName: "self"` (for full-capability PoC and MCP workers) with the corresponding specialist prompt!

### 4.2 Subagent Swarming Protocol & Mandatory Watchdogs

1. **Parallel Fan-Out ("Spam Subagents" Intelligently by Attack Surface)**:
   - For any non-trivial repository or multi-file diff, **do not audit sequentially in a single thread**.
   - Immediately fan out **3 to 6 concurrent subagents** in a single turn using multiple `invoke_subagent` calls:
     - **Worker 1 (`agy-baseline-auditor`)**: Unanchored full-scope baseline vulnerability sweep.
     - **Worker 2 (`agy-threat-architect`)**: Fresh-context architecture & effective-resource boundary review (`threat-model.md`).
     - **Workers 3..N (`agy-packet-investigator`)**: One subagent per high-risk subsystem packet (e.g., Packet A: Auth/RBAC/Tenancy & Session; Packet B: File/Archive/Import/Path Handling; Packet C: SQL/Query/Deserialization/Template Sinks; Packet D: Outbound SSRF/Webhooks/Integrations).
2. **Mandatory `schedule` Watchdog Timer**:
   - Whenever launching a single subagent, attach `schedule({ DurationSeconds: 180, Prompt: "Watchdog: Check security subagent progress", TimerCondition: "<convId>" })`.
   - Whenever launching multiple subagents in parallel, attach `schedule({ DurationSeconds: 180, Prompt: "Watchdog: Check parallel security subagent swarm progress", TimerCondition: "any" })`.
3. **Follow-Up & Lifecycle Management (Native Antigravity Tools Only)**:
   - To send follow-up questions or re-checks to an existing subagent, use `send_message({ Recipient: "<convId>", Message: "..." })` paired with a `schedule` watchdog timer.
   - To check live status or stop a stalled worker, use `manage_subagents({ Action: "list" })` and `manage_subagents({ Action: "kill", ConversationIds: ["<convId>"] })`.

---

## 5. Standard Scan Quickstart Workflow (`record_agy_security_scan_draft` Schema)

To run a complete Standard Scan on a local directory or repository:

1. **Start Scan**:
   ```json
   {
     "ServerName": "agy_security",
     "ToolName": "start_agy_security_standard_scan",
     "Arguments": {
       "targetPath": "C:/path/to/repo",
       "scope": "."
     }
   }
   ```
   Capture `scanId` and `scanDir` from `structuredContent`.
2. **Resolve `SECURITY.md` Policy**:
   ```json
   {
     "ServerName": "agy_security",
     "ToolName": "agy_security_helper",
     "Arguments": {
       "command": "resolve-security-md",
       "args": ["--repo", "C:/path/to/repo", "--list"]
     }
   }
   ```
3. **Checkpoint Threat Model (`complete: false`)**:
   Call `record_agy_security_scan_draft` with `complete: false`, `threatModel: { format: "markdown", origin: "generated", content: "# Threat Model\n..." }`, `findings: []`, and `coverage: { surfaces: [...], explicitExclusions: [], deferred: [] }`.
4. **Spawn Subagent Swarm, Validate & Record Final Draft (`complete: true`)**:
   Fan out parallel `invoke_subagent` workers across packets, validate candidates (`agy-validation`), run attack-path calibration (`agy-attack-path-analysis`), and submit the final validated findings via `record_agy_security_scan_draft` (`severity: { level, rationale }`, `confidence: { level, rationale }`, `remediation: "<string>"`, `provenance: { source: "local_plugin" }`, and `coverage: { surfaces, explicitExclusions, deferred }`).
5. **Complete & Seal Scan**:
   Call `complete_agy_security_scan({ scanId: "<scanId>" })`. This seals `scan-manifest.json`, `findings.json`, `coverage.json`, and generates `report.md`, `threatmodel.md`, and `exports/results.sarif` (`findings.sarif.json`).
6. **Optional Benchmark Evaluation**:
   If auditing `invoice-desk` or any target with an `expected-findings.json`, run `agy_security_evaluate_benchmark({ scanId: "<scanId>" })` to get automated precision/recall metrics.
