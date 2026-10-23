# AGY-Security

**AGY-Security** (`@agy/agy-security-mcp`) is an end-to-end Application Security Workbench, Multi-Agent Audit Suite, Dynamic PoC Validator, and Ground-Truth Benchmark Engine built natively for **Google Antigravity 2.0 and Antigravity CLI**.

---

## Credits and Attribution

This project is based on and ported from the original [**openai/codex-security**](https://github.com/openai/codex-security) architecture by OpenAI. Full credit goes to the original Codex Security authors for the core SQLite workbench schema, native Rust file-enumeration addon, SARIF 2.1.0 / Markdown report contract, obligation-ledger methodology, and the `invoice-desk` benchmark fixture.

**AGY-Security** re-architects, unlocks, and upgrades the entire stack to run natively inside Google Antigravity 2.0 without external account gating, legacy Codex CLI dependencies, or multi-file prompt-reading overhead.

---

## What is New and Upgraded (Codex Security vs. AGY-Security)

| Capability | Original `codex-security` | Upgraded `AGY-Security` (Antigravity 2.0) |
| :--- | :--- | :--- |
| **Access and Entitlements** | Gated behind external ChatGPT Daybreak entitlement checks (`cyber_trusted_access`). | **100% Unrestricted Local Access**: `Daybreak Red` (`tac3`) and `Daybreak Blue` (`tac1`) are permanently granted locally with zero account restrictions. |
| **Trigger Mechanism** | Requires explicit slash commands or manual skill selection. | **Zero-Slash Automatic Trigger**: Automatically activates on any security-related user request via `<user_rules>` without waiting for `/agy-...` commands. |
| **Token and Latency Overhead** | Chain-reads 8+ reference Markdown files, 50 KB JSON schemas, and Python scripts before scanning. | **Zero-Read Pre-Compiled Knowledge Fast-Path**: Pre-compiles all tool contracts, schemas, and prompts into `rules/AGENTS.md` and `knowledge/`. Starts scanning on Turn 1 with zero `.py` or `.json` reads (87% smaller draft schema cache). |
| **Multi-Agent Orchestration** | Uses proprietary Codex primitives (`followup_task`, `fork_turns=none`, `interrupt_agent`) and spawns external `@openai/agy` CLI workers. | **Max-Ping Parallel Subagent Swarm**: Uses 6 native Antigravity subagents (`agents/*.md`), parallel `invoke_subagent` fan-out, `send_message`, `manage_subagents`, and `schedule` watchdog timers. |
| **Deep Scan Execution** | Blocks waiting for an external `@openai/agy` SDK binary subprocess. | **Native Antigravity Deep Scan**: `start_agy_security_deep_scan` registers `mode: "deep"` directly in SQLite (`orchestration: "antigravity_subagents"`) with worker-surface coverage merging (`deep_scan_worker_threads`) and accepts direct semantic draft sealing. |
| **External Scanner Ingestion** | Requires manual external CLI scripts to normalize third-party reports. | **Built-in Zero-Dependency Scanner Importers (`mcp/sdk/`)**: Directly imports and normalizes Snyk, Semgrep, Endor Labs, Wiz, and GitHub Code Scanning / Security Advisories into the 53-migration SQLite workbench (`external_source_reports`). |
| **Finding Owner Attribution** | Requires manual `git blame` / `CODEOWNERS` lookups by the model. | **Deterministic Owner Attribution Engine**: `suggest_agy_security_finding_owners` combines `CODEOWNERS`, line-range `git blame`, and recent `git log` history in a single deterministic tool call. |
| **MCP Tool Count** | 51 workbench tools. | **58 MCP Tools**: Adds 7 native diagnostic, helper, lab-runner, benchmark-scoring, external-report import, and owner-attribution tools (`agy_security_doctor`, `agy_security_helper`, `agy_security_run_lab_tests`, `agy_security_evaluate_benchmark`, `import_agy_security_external_findings`, `list_agy_security_imported_findings`, `suggest_agy_security_finding_owners`). |
| **IDE Output Formatting** | Emits legacy `::code-comment{...}` directives and `app://...` connector links. | Emits native Antigravity clickable `[file.ext](file:///abs/path#L10-L20)` links, `[P0 / Critical]`..`[P3 / Low]` priority tags, and integrates with `github-mcp-server` and `gh` CLI. |

---

## Key Features and Supported Workflows

### 1. Six Bundled Specialist Subagents (`agents/*.md`)
Automatically discovered by Google Antigravity 2.0 and invoked in parallel during scans:
- **`agy-security-orchestrator`**: Master coordinator that initializes SQLite scans, resolves `SECURITY.md` policies, runs fast static pre-screening, and fans out parallel worker subagents with `schedule` watchdogs.
- **`agy-baseline-auditor`**: Independent, unanchored full-repository static vulnerability and hardcoded-secrets/private-keys auditor.
- **`agy-threat-architect`**: Source-backed security architecture reviewer that maps trust boundaries, attacker capabilities, and the `effectiveResources` configuration-precedence verification table.
- **`agy-packet-investigator`**: Parallel packet investigator (spawned 2 to 4 instances concurrently) tracing forward injection sinks, authentication/authorization boundaries, multi-tenant isolation (IDOR), and business-logic state transitions.
- **`agy-poc-validator`**: Runtime and exploitability validator that executes isolated unit tests, local reproduction harnesses (`Workspace: "branch"`), or deterministic static traces before a candidate is reported.
- **`agy-patch-reviewer`**: Adversarial red-team reviewer that challenges candidate fixes for encoding/symlink/sibling-route bypasses and functional regressions.

### 2. Eighteen Specialized Security Skills (`skills/*/SKILL.md`)
- **`agy-security`**: Master hub and 58-tool reference.
- **`agy-security-scan`**: Standard single-pass repository or scoped-folder security audit.
- **`agy-deep-security-scan`**: Multi-pass, variance-reducing exhaustive repository audit using parallel subagent swarms.
- **`agy-security-diff-scan`**: Pull request, commit range, branch diff, and working-tree patch vulnerability audit with JSONL obligation ledgers.
- **`agy-threat-model`**: Standalone or in-scan source-backed threat modeling (`threatmodel.md`).
- **`agy-finding-discovery`**: Structured candidate vulnerability discovery.
- **`agy-validation`**: Dynamic PoC, crash/ASan/debugger, and unit-test validation.
- **`agy-attack-path-analysis`**: Source-to-sink reachability, counterevidence verification, and severity calibration.
- **`agy-triage-finding`**: Static triage of imported SARIF reports, CVEs, GitHub Security Alerts, and Jira/Linear tickets.
- **`agy-fix-finding`**: Minimal repository-native security patching with pre-patch boundary investigation and post-patch bypass review.
- **`agy-verify-fix`**: Read-only verification that a patch closes the vulnerability without regressions.
- **`agy-assess-patch-risk`**: Blast-radius, contract-stability, and auto-merge eligibility assessment for patches.
- **`agy-vulnerability-writeup`**: Researcher-grade vulnerability disclosure write-ups and self-contained PoCs.
- **`agy-propose-security-hardening`**: Architectural security hardening portfolios with before/after Mermaid diagrams.
- **`agy-define-security-policy`**: Repository `SECURITY.md` policy authoring and directory-scoped policy resolution.
- **`agy-track-findings`**: Issue tracking synchronization for GitHub Issues, GitHub Security Advisories, Jira, and Linear.
- **`agy-cloud-findings`**: Query and inspect historical scans, global findings, triage states, and remediation records across repositories.
- **`agy-publish-findings`**: Import, normalize, and store external scanner findings (Snyk, Semgrep, Endor Labs, Wiz, GitHub Code Scanning / Security Advisories) into the local SQLite workbench (`external_source_reports`).

### 3. Pre-Compiled Knowledge Base (`knowledge/*.md`)
Designed to eliminate LLM token waste and file-reading latency:
- **`00_PRECOMPILED_MASTER_CONTRACT.md`**: Complete 4-step fast-path execution contract, exact JSON payload template for `record_agy_security_scan_draft`, and strict schema invariants.
- **`01_HIGH_SIGNAL_SINK_PATTERNS.md`**: Pre-built `ripgrep` (`rg`), `semgrep`, `bandit`, and `pip-audit` commands for Python, JavaScript/TypeScript/Node.js, PHP, Go, Rust, C/C++/Android NDK, and secret/key exposure.
- **`02_SEVERITY_AND_TAXONOMY_MATRIX.md`**: Canonical `ruleId` slugs, `taxonomy.cwe` mappings, and impact-vs-likelihood severity calibration rules.

### 4. Fifty-Eight MCP Tools (`mcp/server.mjs`)
- **Scan Lifecycle**: `start_agy_security_standard_scan`, `start_agy_security_deep_scan`, `start_agy_security_prompt_only_scan`, `start_agy_security_scan`, `get_agy_security_scan`, `get_agy_security_scan_context`, `update_agy_security_scan_context`, `update_agy_security_scan_progress`, `complete_agy_security_scan`, `cancel_agy_security_scan`, `fail_agy_security_scan`, `recover_agy_security_scan_results`, `list_agy_security_scans`, `list_agy_security_repositories`.
- **Semantic Drafts, Ledgers, and Artifacts**: `record_agy_security_scan_draft`, `get_agy_security_completed_scan`, `prepare_agy_security_review_items`, `list_agy_security_review_items`, `record_agy_security_discovery_candidates`, `list_agy_security_candidates`, `record_agy_security_candidate_validations`, `record_agy_security_candidate_attack_paths`, `save_agy_security_artifact`, `read_agy_security_artifact`, `export_agy_security_findings`.
- **Triage, Remediation, and Tracking**: `list_agy_security_findings`, `list_agy_security_global_findings`, `set_agy_security_finding_triage`, `request_agy_security_finding_remediation`, `request_agy_security_finding_remediation_action`, `set_agy_security_finding_remediation`, `get_agy_security_finding_issues`, `record_agy_security_finding_issues`.
- **External Scanner Importers and Owner Attribution**: `import_agy_security_external_findings`, `list_agy_security_imported_findings`, `suggest_agy_security_finding_owners`.
- **Antigravity Diagnostics, Helpers, and Lab Benchmarking**: `agy_security_doctor`, `agy_security_helper`, `agy_security_run_lab_tests`, `agy_security_evaluate_benchmark`, `get_agy_security_daybreak_access`.

---

## Requirements

- **Node.js**: `v20.0.0` or newer (tested on `v24.14.1`)
- **Python**: `3.10` or newer (tested on `3.14`) with `jsonschema` and `brotli` installed
- **Git**: `2.30+`
- **Ripgrep (`rg`)**: Required for fast offline source search
- **Optional Static Analysis CLI Tools** (auto-detected by `agy_security_doctor`):
  - `semgrep` (`pip install semgrep`)
  - `bandit` (`pip install bandit`)
  - `pip-audit` (`pip install pip-audit`)
  - `gh` (GitHub CLI for advisory/issue tracking)

---

## How to Install

### Step 1: Clone into the Antigravity Plugins Directory

**Windows (PowerShell):**
```powershell
git clone https://github.com/onlytrisdev/agy-security.git "$HOME\.gemini\config\plugins\agy-security"
cd "$HOME\.gemini\config\plugins\agy-security"
```

**macOS / Linux (Bash):**
```bash
git clone https://github.com/onlytrisdev/agy-security.git "$HOME/.gemini/config/plugins/agy-security"
cd "$HOME/.gemini/config/plugins/agy-security"
```

### Step 2: Install Python Dependencies and Optional Scanners

```bash
pip install jsonschema brotli bandit pip-audit semgrep
```

### Step 3: Run the One-Command Knowledge and MCP Installer

Run `scripts/install_agy_knowledge.py` to automatically:
1. Register the `agy_security` MCP server and `AGY_SECURITY_KNOWLEDGE_BASE` in `~/.gemini/config/mcp_config.json`.
2. Install the global Zero-Slash Auto-Trigger rule in `~/.gemini/config/rules/agy_security_auto_trigger.md`.
3. Compact the MCP tool schema cache in `~/.gemini/antigravity/mcp/agy_security/*.json` for zero-token-waste execution.
4. Mirror the plugin skills and subagents into `~/.gemini/config/skills/agy-security`.

```bash
python scripts/install_agy_knowledge.py
```

Expected output:
```json
{
  "status": "installed",
  "knowledgeFiles": [
    "00_PRECOMPILED_MASTER_CONTRACT.md",
    "01_HIGH_SIGNAL_SINK_PATTERNS.md",
    "02_SEVERITY_AND_TAXONOMY_MATRIX.md"
  ],
  "mcpConfigUpdated": true
}
```

### Step 4: Verify Installation with `agy_security_doctor`

You can verify the MCP server, native addon, SQLite state database, CLI scanners, and bundled subagents directly from the terminal or inside Antigravity:

```bash
python scripts/workbench_db.py --state-dir "$HOME/.gemini/mcp/agy-security/state" database-info
```

Or inside an Antigravity chat session, call:
```json
{
  "ServerName": "agy_security",
  "ToolName": "agy_security_doctor",
  "Arguments": {}
}
```

---

## Manual MCP Configuration (`~/.gemini/config/mcp_config.json`)

If you prefer to configure `mcp_config.json` manually, add the following entry under `"mcpServers"`:

```json
{
  "mcpServers": {
    "agy_security": {
      "command": "node",
      "args": [
        "C:\\Users\\<USERNAME>\\.gemini\\config\\plugins\\agy-security\\mcp\\server.mjs",
        "--stdio"
      ],
      "env": {
        "AGY_SECURITY_PLUGIN_ROOT": "C:\\Users\\<USERNAME>\\.gemini\\config\\plugins\\agy-security",
        "AGY_SECURITY_STATE_DIR": "C:\\Users\\<USERNAME>\\.gemini\\mcp\\agy-security\\state",
        "AGY_SECURITY_KNOWLEDGE_BASE": "C:\\Users\\<USERNAME>\\.gemini\\config\\plugins\\agy-security\\knowledge",
        "PYTHON": "python",
        "PYTHONUTF8": "1",
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

---

## How to Use

Because **Zero-Slash Auto-Trigger** is enabled via `rules/AGENTS.md` and `~/.gemini/config/rules/agy_security_auto_trigger.md`, you do **not** need to type `/agy-...` slash commands. Simply ask naturally in any language:

- **Full Repository Audit**:
  > "Audit this repository for security vulnerabilities and generate the full report."
- **Exhaustive Multi-Pass Deep Scan**:
  > "Run a deep multi-pass security scan on this codebase using parallel subagents."
- **PR / Commit / Working-Tree Diff Review**:
  > "Review my current git diff for security issues and regressions."
- **Threat Model Generation**:
  > "Build a source-backed threat model and trust boundary map for this project."
- **Dynamic PoC Validation & Patching**:
  > "Validate this vulnerability with a PoC test, implement the minimal fix, and run adversarial bypass review."
- **Built-in Lab Benchmark (`examples/invoice-desk`)**:
  > "Run the invoice-desk security benchmark and evaluate recall and precision."

---

## Repository Structure

```text
agy-security/
├── agents/                     # 6 Native Antigravity 2.0 Specialist Subagents (*.md)
├── assets/                     # Plugin logo and visual assets
├── examples/
│   ├── completed-scan/         # Reference sealed scan bundle
│   └── invoice-desk/           # Built-in vulnerable app & ground-truth QA benchmark
├── knowledge/                  # Pre-compiled Zero-Read Knowledge Base (AGY_SECURITY_KNOWLEDGE_BASE)
├── mcp/                        # MCP Server runtime (server.mjs, helpers.mjs, sdk/, native Rust .node addons)
├── references/                 # Detailed audit, threat-model, and report specifications
├── rules/
│   └── AGENTS.md               # Pre-compiled Turn-0 Zero-Read Fast-Path & Auto-Trigger rules
├── schemas/                    # Canonical JSON Schemas (scan-manifest, findings, coverage, external-findings, SARIF)
├── scripts/                    # Python workbench, SQLite state manager, and install_agy_knowledge.py
├── shared/                     # Shared severity constants and 53 SQLite workbench migrations
├── skills/                     # 18 Specialized Security Skills (SKILL.md)
├── plugin.json                 # Antigravity Plugin manifest (v1.0.0)
└── README.md                   # Documentation
```

---

## License

Apache-2.0 (preserving original license notices from `openai/codex-security`).
