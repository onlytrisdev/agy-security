# AGY Security Auto-Trigger, Zero-Read Pre-Compiled Knowledge & Max-Ping Swarm Rules

## 0. STRICT ZERO-READ / ZERO-TOKEN-WASTE MANDATE
To save time and context tokens, **all `AGY-Security` tool contracts, JSON schemas, and subagent prompts are ALREADY pre-compiled in this rule and in `agents/*.md`**. When triggered:
- **NEVER read** any `.py` file in `plugins/agy-security/scripts/` or `skills/agy-security/scripts/` (`workbench_*.py`, `scan_contract.py`, `finalize_scan_contract.py`, etc.). Those are internal backend scripts, NOT documentation.
- **NEVER read** any `.mjs` file in `mcp/` or `.json` schema file in `schemas/` or `antigravity/mcp/agy_security/*.json` (do NOT read `record_agy_security_scan_draft.json`).
- **NEVER chain-read** `references/scan-prologue.md`, `references/core-scan.md`, `references/threat-model.md`, `references/final-report.md`, `references/finding-detail-fields.md`, or `examples/completed-scan/*`.
- **Start scanning the user's target repository on Turn 1 immediately** using the pre-compiled 4-Step Fast-Path below!

---

## 1. Automatic Zero-Slash Triggering (No `/agy-...` Required)
Automatically activate **AGY-Security** whenever the user's request touches **any** security concern in any language without waiting for explicit `/agy-...` slash commands:
- Security audits, repository/directory vulnerability scans, or PR/commit/branch/working-tree diff security reviews
- Authentication, authorization, session/JWT/OAuth/mTLS, RBAC/ABAC, multi-tenant isolation, IDOR, SQLi, XSS, SSRF, RCE, path traversal, deserialization, or hardcoded secret/key checks
- Threat modeling, attack-path analysis, PoC exploitability validation, finding triage, security patching, fix verification, patch-risk assessment, vulnerability write-ups, or architectural hardening

---

## 2. Pre-Compiled 4-Step Fast-Path (Immediate Execution Without Reading Skill/Schema Files)

### Step 1 — Start the Durable Scan on Turn 1 (`call_mcp_tool` with `ServerName: "agy_security"`)
- **Standard Repo / Folder Scan**:
  `call_mcp_tool({ ServerName: "agy_security", ToolName: "start_agy_security_standard_scan", Arguments: { targetPath: "<abs_path>", scope: ".", userContext: "<optional_focus>" } })`
- **Exhaustive Multi-Pass Deep Scan**:
  `call_mcp_tool({ ServerName: "agy_security", ToolName: "start_agy_security_deep_scan", Arguments: { targetPath: "<abs_path>", scope: ".", userContext: "<optional_focus>" } })`
- **PR / Commit / Working-Tree Diff Scan**:
  `call_mcp_tool({ ServerName: "agy_security", ToolName: "start_agy_security_prompt_only_scan", Arguments: { mode: "diff", targetPath: "<abs_path>", scope: ".", diffTarget: { kind: "working_tree" } } })`
*(Optional helper to resolve `SECURITY.md`: `call_mcp_tool({ ServerName: "agy_security", ToolName: "agy_security_helper", Arguments: { command: "resolve-security-md", args: ["--repo", "<abs_path>", "--scope", ".", "--out", "-"] } })`)*

### Step 2 — Max-Ping Parallel Subagent Swarm (`invoke_subagent` + `schedule`)
For any repository, module, or multi-file audit, fan out parallel subagents in a **single turn** (each subagent in `agents/*.md` already has its complete system prompt pre-compiled):
1. `invoke_subagent({ TypeName: "agy-baseline-auditor", Role: "Baseline & Secrets Auditor", Prompt: "Audit <targetPath> (scope: <scope>) for vulnerabilities and hardcoded secrets/keys. Return JSON with findings, resolved_questions, reviewed_files." })`
2. `invoke_subagent({ TypeName: "agy-threat-architect", Role: "Threat Model Architect", Prompt: "Build source-backed threatModel and effectiveResources table for <targetPath>. Return JSON with threatModel, effectiveResources, resolved_questions." })`
3. `invoke_subagent({ TypeName: "agy-packet-investigator", Role: "Packet Investigator #1 (Injection & Sinks)", Prompt: "Trace attacker inputs to SQLi, command/code injection, SSRF, path traversal, deserialization, and XSS sinks in <targetPath>." })`
4. `invoke_subagent({ TypeName: "agy-packet-investigator", Role: "Packet Investigator #2 (AuthN/AuthZ & Logic)", Prompt: "Trace auth, JWT/session, RBAC, multi-tenant isolation, IDOR, and business-logic state transitions in <targetPath>." })`
5. **Mandatory Watchdog**: `schedule({ DurationSeconds: 180, TimerCondition: "any", Prompt: "Watchdog: Check AGY-Security subagent swarm status" })`.
*(For high-priority candidate bugs or fixes, optionally spawn `agy-poc-validator` or `agy-patch-reviewer`.)*

### Step 3 — Submit Semantic Draft (`record_agy_security_scan_draft`)
Call `call_mcp_tool` with `ServerName: "agy_security"`, `ToolName: "record_agy_security_scan_draft"`, and this **exact** pre-compiled JSON schema:
```json
{
  "scanId": "<UUID from Step 1>",
  "complete": true,
  "scope": {
    "summary": "Security audit of <target>",
    "artifactsReviewed": ["."],
    "validationMode": "static_and_poc"
  },
  "threatModel": {
    "summary": "Product purpose, main components, data flows, and deployment.",
    "assets": ["Sensitive data, credentials, tenant state"],
    "trustBoundaries": ["Entry point -> handler (path/to/file.ext:10)"],
    "attackerCapabilities": ["Unauthenticated caller", "Authenticated tenant user"],
    "securityObjectives": ["Enforce authz, tenant isolation, and input parameterization"],
    "assumptions": ["Deployment assumptions and unknowns"]
  },
  "findings": [
    {
      "ruleId": "vulnerability-family.specific-sink",
      "title": "Concise vulnerability title",
      "summary": "One-sentence summary of the broken control and impact.",
      "severity": {
        "level": "high",
        "rationale": "Why impact and likelihood yield this severity (critical|high|medium|low|informational)."
      },
      "confidence": {
        "level": "high",
        "rationale": "Why source trace / PoC establishes this confidence (high|medium|low)."
      },
      "taxonomy": {
        "category": "Primary Broken Security Control Name",
        "cwe": ["CWE-22"]
      },
      "locations": [
        { "path": "relative/path.py", "startLine": 10, "endLine": 15, "role": "root_control" }
      ],
      "codeEvidence": [
        {
          "id": "ev-1",
          "label": "Vulnerable sink or missing guard",
          "path": "relative/path.py",
          "startLine": 10,
          "endLine": 15,
          "code": "exact source lines from file",
          "explanation": "Why these lines are vulnerable."
        }
      ],
      "rootCause": { "summary": "Root broken control explanation.", "evidenceRefs": ["ev-1"] },
      "validation": {
        "status": "validated",
        "method": "static_and_poc",
        "summary": "How reachability/exploitability was verified.",
        "counterEvidence": ["Checked upstream callers/middleware; no guard neutralizes input."]
      },
      "attackPath": {
        "summary": "End-to-end attacker story from entry point to impact.",
        "steps": ["Step 1", "Step 2"],
        "dataflow": { "summary": "source -> transformation -> sink", "source": "file.py:5", "sink": "file.py:12" },
        "reachability": { "summary": "Reachable by attacker via route/API.", "attacker": "Attacker role", "entrypoint": "Route/API" }
      },
      "remediation": "Minimal safe code change at the shared boundary.",
      "provenance": { "source": "local_plugin" }
    }
  ],
  "coverage": {
    "surfaces": [
      {
        "id": "surf-1",
        "label": "Reviewed subsystem name",
        "disposition": "reported",
        "notes": "Cited path:line evidence and disposition (reported | no_issue_found | rejected | not_applicable | needs_follow_up)."
      }
    ],
    "explicitExclusions": [],
    "deferred": [],
    "resolvedDeferred": [],
    "openQuestions": []
  }
}
```
**Strict Schema Invariants**:
- NEVER put `includePaths` or `excludePaths` inside `scope` or `coverage`.
- `severity` and `confidence` MUST be objects `{ level, rationale }`, NEVER bare strings.
- `remediation` MUST be a string, NEVER an object.
- Use `codeEvidence` (with `code`, never `snippet`), `rootCause` (never `root_cause`), `dataflow` (never `dataFlow`).
- `coverage.surfaces[].disposition` MUST be one of: `"reported"`, `"no_issue_found"`, `"rejected"`, `"not_applicable"`, `"needs_follow_up"`.

### Step 4 — Seal the Scan Once (`complete_agy_security_scan`)
Call `call_mcp_tool({ ServerName: "agy_security", ToolName: "complete_agy_security_scan", Arguments: { scanId: "<UUID>" } })`.
This automatically seals `scan-manifest.json`, `findings.json`, `coverage.json`, `report.md`, and `exports/findings.sarif.json`. Present findings with clickable `[file.ext](file:///abs/path#L10-L15)` links and `[P0/Critical]`..`[P3/Low]` tags.
