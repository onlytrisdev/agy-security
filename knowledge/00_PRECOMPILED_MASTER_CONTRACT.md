# AGY-Security Pre-Compiled Master Contract (Zero-Read Fast-Path)

> **CRITICAL TOKEN-SAVING RULE**: This knowledge base and `<user_rules>` already contain the complete, authoritative tool signatures and JSON schemas for `AGY-Security`.
> **NEVER** read `scripts/*.py`, `mcp/*.mjs`, `schemas/**/*.json`, `examples/**`, or `antigravity/mcp/agy_security/*.json` during a scan.

---

## 1. 4-Step Zero-Read Scan Execution Fast-Path

### Step 1 — Register the Durable Scan Immediately (Turn 1)
Call `call_mcp_tool` with `ServerName: "agy_security"`:
- **Standard Repo / Folder Scan**:
  ```json
  {
    "ServerName": "agy_security",
    "ToolName": "start_agy_security_standard_scan",
    "Arguments": {
      "targetPath": "C:/absolute/path/to/repo",
      "scope": ".",
      "userContext": "Optional security focus"
    }
  }
  ```
- **Multi-Pass Deep Scan**:
  ```json
  {
    "ServerName": "agy_security",
    "ToolName": "start_agy_security_deep_scan",
    "Arguments": {
      "targetPath": "C:/absolute/path/to/repo",
      "scope": ".",
      "userContext": "Optional security focus"
    }
  }
  ```
- **PR / Commit / Branch / Working-Tree Diff Scan**:
  ```json
  {
    "ServerName": "agy_security",
    "ToolName": "start_agy_security_prompt_only_scan",
    "Arguments": {
      "mode": "diff",
      "targetPath": "C:/absolute/path/to/repo",
      "scope": ".",
      "diffTarget": { "kind": "working_tree" }
    }
  }
  ```
*(Returns `scanId`, `scanDir`, and optional `handoffClaimToken`.)*

---

### Step 2 — Fan-Out Parallel Specialist Subagents (`invoke_subagent` + `schedule`)
All 6 specialist subagents in `plugins/agy-security/agents/*.md` already have their full instructions pre-compiled. Do **NOT** read `references/core-scan.md` or `references/threat-model.md` to build prompts—just pass the target path, scope, and assigned packet focus:
1. `invoke_subagent({ TypeName: "agy-baseline-auditor", Role: "Baseline & Secrets Auditor", Prompt: "Audit <targetPath> (scope: <scope>) for high-signal vulnerabilities and hardcoded secrets. Return JSON with findings, resolved_questions, reviewed_files." })`
2. `invoke_subagent({ TypeName: "agy-threat-architect", Role: "Threat Model Architect", Prompt: "Map architecture, trustBoundaries, effectiveResources, and attacker scenarios for <targetPath>. Return JSON with threatModel, effectiveResources, resolved_questions." })`
3. `invoke_subagent({ TypeName: "agy-packet-investigator", Role: "Packet Investigator #1 (Injection & Sinks)", Prompt: "Trace attacker-controlled inputs to SQL, command, SSRF, file/path, deserialization, and XSS sinks in <targetPath>." })`
4. `invoke_subagent({ TypeName: "agy-packet-investigator", Role: "Packet Investigator #2 (AuthN/AuthZ & Logic)", Prompt: "Trace authentication, RBAC/ABAC, multi-tenant isolation, IDOR, and state transition boundaries in <targetPath>." })`
5. Attach Watchdog: `schedule({ DurationSeconds: 180, TimerCondition: "any", Prompt: "Watchdog: Check AGY-Security subagent swarm" })`.

---

### Step 3 — Record the Semantic Scan Draft (`record_agy_security_scan_draft`)
Use this **exact** schema-validated structure (never read `scan-draft.schema.json` or `scripts/*.py`):

```json
{
  "ServerName": "agy_security",
  "ToolName": "record_agy_security_scan_draft",
  "Arguments": {
    "scanId": "<UUID from Step 1>",
    "complete": true,
    "scope": {
      "summary": "Full security audit of <target>",
      "artifactsReviewed": ["src/"],
      "validationMode": "static_and_poc"
    },
    "threatModel": {
      "summary": "Concise architecture, components, data flow, and deployment summary.",
      "assets": ["User credentials", "Tenant database records"],
      "trustBoundaries": ["HTTP API -> Controller (src/server.py:42)"],
      "attackerCapabilities": ["Unauthenticated remote caller", "Authenticated low-privilege tenant user"],
      "securityObjectives": ["Enforce tenant isolation and parameterize all queries"],
      "assumptions": ["TLS terminated at reverse proxy"]
    },
    "findings": [
      {
        "ruleId": "path-traversal.attachment-download",
        "title": "Arbitrary file read via path traversal in attachment download",
        "summary": "User-controlled query parameter flows into send_file without path containment check.",
        "severity": {
          "level": "high",
          "rationale": "Allows unauthenticated/tenant user to read arbitrary readable files on host.",
          "score": 8.2
        },
        "confidence": {
          "level": "high",
          "rationale": "Verified direct source-to-sink flow and reproduced with PoC."
        },
        "taxonomy": {
          "category": "Missing Path Containment Check",
          "cwe": ["CWE-22"]
        },
        "locations": [
          { "path": "src/server.py", "startLine": 253, "endLine": 256, "role": "root_control" }
        ],
        "codeEvidence": [
          {
            "id": "ev-1",
            "label": "Unchecked path join in download handler",
            "path": "src/server.py",
            "startLine": 253,
            "endLine": 256,
            "code": "target = ATTACHMENT_DIR / name\nreturn send_file(target)",
            "explanation": "Path join allows '../' segments to escape ATTACHMENT_DIR."
          }
        ],
        "rootCause": {
          "summary": "Missing canonical path resolution (.resolve()) and prefix containment check (.is_relative_to()).",
          "evidenceRefs": ["ev-1"]
        },
        "validation": {
          "status": "validated",
          "method": "poc_and_static_trace",
          "summary": "Verified that '../' payloads bypass the join and read parent files.",
          "counterEvidence": ["Checked middleware; no path normalization strips '../' on query params."]
        },
        "attackPath": {
          "summary": "Attacker supplies ?name=../../etc/passwd to GET /attachments/download.",
          "steps": [
            "Send GET request with traversal payload in query parameter",
            "Handler joins ATTACHMENT_DIR with unvalidated parameter",
            "send_file streams arbitrary host file in HTTP response"
          ],
          "dataflow": {
            "summary": "request.args['name'] -> ATTACHMENT_DIR / name -> send_file(target)",
            "source": "src/server.py:251",
            "sink": "src/server.py:256"
          },
          "reachability": {
            "summary": "Directly reachable by any caller able to hit GET /attachments/download.",
            "attacker": "Remote HTTP caller",
            "entrypoint": "GET /attachments/download"
          }
        },
        "remediation": "Resolve the candidate path with Path.resolve() and verify target.is_relative_to(ATTACHMENT_DIR.resolve()) before calling send_file.",
        "provenance": {
          "source": "local_plugin"
        }
      }
    ],
    "coverage": {
      "surfaces": [
        {
          "id": "surface-attachments",
          "label": "Attachment download and file handling",
          "disposition": "reported",
          "notes": "Reviewed src/server.py:240-270; reported path-traversal.attachment-download."
        },
        {
          "id": "surface-auth",
          "label": "Session authentication middleware",
          "disposition": "no_issue_found",
          "notes": "Verified HMAC verification and expiration checks in src/auth.py:10-85."
        }
      ],
      "explicitExclusions": [],
      "deferred": [],
      "resolvedDeferred": [],
      "openQuestions": []
    }
  }
}
```

### Strict Schema Rules for `record_agy_security_scan_draft` (Avoid Validation Errors!)
1. `scope`: Do **NOT** pass `includePaths` or `excludePaths` inside `scope` (`includePaths: false`). Only pass `summary`, `artifactsReviewed`, `validationMode`, `limitations`.
2. `findings[].severity`: Must be an **object** `{ "level": "critical"|"high"|"medium"|"low"|"informational", "rationale": "..." }`, NEVER a bare string.
3. `findings[].confidence`: Must be an **object** `{ "level": "high"|"medium"|"low", "rationale": "..." }`, NEVER a bare string.
4. `findings[].remediation`: Must be a **non-empty string**, NEVER an object.
5. `findings[].codeEvidence`: Use key `codeEvidence` (NEVER `code_evidence`), and inside each item use `code` (NEVER `snippet`). `id` must match `^[a-z0-9][a-z0-9._/-]*$`.
6. `findings[].rootCause`: Use `rootCause` (NEVER `root_cause`).
7. `findings[].attackPath.dataflow`: Use lowercase `dataflow` (NEVER `dataFlow` or `data_flow`).
8. `findings[].provenance`: Must include `{ "source": "local_plugin" }`.
9. `coverage`: Must include `"surfaces"` (each with `label` and `disposition` in `["reported", "no_issue_found", "rejected", "not_applicable", "needs_follow_up"]`), `"explicitExclusions": []`, and `"deferred": []`. Do **NOT** pass `includePaths`, `excludePaths`, `mode`, or `inventoryStrategy` inside `coverage`.

---

### Step 4 — Seal the Scan (`complete_agy_security_scan`)
```json
{
  "ServerName": "agy_security",
  "ToolName": "complete_agy_security_scan",
  "Arguments": {
    "scanId": "<UUID from Step 1>"
  }
}
```
This single call seals `scan-manifest.json`, `findings.json`, `coverage.json`, and generates `report.md`, `threatmodel.md`, and `exports/findings.sarif.json`.
