---
name: agy-cloud-findings
description: Read existing AGY Security global findings, scan history, reports, recorded triage/remediation states, and repository status from the AGY Security workbench and connected GitHub repositories. Use for read-only finding queries, scan status lookups, and finding links, not for launching new scans or mutating repository code.
---

# AGY Cloud & Global Findings Reader

Use the `agy_security` MCP server tools (`ServerName: "agy_security"`) to query, filter, and inspect existing findings, completed scan reports, validation artifacts, and remediation statuses across all indexed repositories. This workflow is strictly read-only: do not launch or cancel scans, edit findings, generate patches, or modify code unless the user explicitly switches to a scan or remediation skill.

## 1. Resolve Repositories & Targets

Call `list_agy_security_repositories` or `inspect_agy_security_target` via `call_mcp_tool` (`ServerName: "agy_security"`) to discover indexed repositories and targets:

```json
{
  "ServerName": "agy_security",
  "ToolName": "list_agy_security_repositories",
  "Arguments": {}
}
```

- Every indexed repository provides its `repositoryId`, `displayName`, `rootPath`, `remoteUrl`, finding counts by severity, and latest scan summary.
- When the user specifies a repository name, URL, or path, match it against `list_agy_security_repositories` or pass `targetPath` to `inspect_agy_security_target`.
- If the user asks for findings across all accessible repositories, query global findings directly with `list_agy_security_global_findings`.

## 2. List & Filter Findings

Use `list_agy_security_global_findings` for cross-repository queries or `list_agy_security_findings` for a specific scan or repository:

```json
{
  "ServerName": "agy_security",
  "ToolName": "list_agy_security_global_findings",
  "Arguments": {
    "repositoryId": "<optional_repo_id>",
    "severities": ["critical", "high"],
    "statuses": ["open", "triaged"],
    "search": "<optional_keyword_or_rule_id>",
    "limit": 50
  }
}
```

- Supported filters include `repositoryId`, `scanId`, `severities` (`critical`, `high`, `medium`, `low`), `statuses` (`open`, `triaged`, `fixed`, `false_positive`, `ignored`), `categories`, `search`, `limit`, and `cursor`.
- Follow returned `nextCursor` values with the same filters when a complete list or count is requested.
- Preserve stable finding identifiers (`findingId` starting with `asf_`, `occurrenceId` starting with `occ_`, and `fingerprints.primary` under `agy-security/v1`).

## 3. Read Detailed Evidence, Reports & Remediation Status

To inspect the complete evidence, code snippets, validation method, attack path, and report prose for a finding or scan:

1. **Completed Scan Bundle**: Call `get_agy_security_completed_scan({ scanId })` to retrieve the sealed `scan-manifest.json`, `findings.json`, `coverage.json`, `report.md`, and `threatmodel.md`.
2. **Supplemental Evidence & Write-ups**: Call `read_agy_security_artifact({ scanId, storage: "persistent", path: "<relative_path>" })` to read per-finding write-ups (`findings/<slug>/<slug>.md`), PoC artifacts (`artifacts/02_discovery/validation_artifacts/<candidate_id>/...`), or hardening portfolios (`hardening/hardening.md`).
3. **External Tracker Links**: Call `get_agy_security_finding_issues({ findingId })` to inspect linked GitHub Issues, GitHub Security Advisories, Jira tickets, or Linear issues.
4. **Export Formats**: When the user asks to read or export findings in SARIF, JSON, or CSV format, call `export_agy_security_findings({ scanId, format: "sarif" | "json" | "csv" })`.

Keep these records distinct in your response:
- **Triage & Lifecycle Status**: The recorded workbench triage status (`open`, `triaged`, `fixed`, `false_positive`, `ignored`) and any reviewer notes.
- **Validation Evidence**: The recorded validation method (`poc`, `unit_test`, `asan`, `debugger`, `static_trace`), assertions, and limitations.
- **Remediation & Patch State**: Recorded remediation state and verification status.
- **Tracked Issues**: External issue links returned by `get_agy_security_finding_issues`.

## 4. Read Scan History & Status

Use `list_agy_security_scans` and `get_agy_security_scan` to inspect historical or currently running scans:

```json
{
  "ServerName": "agy_security",
  "ToolName": "list_agy_security_scans",
  "Arguments": {
    "repositoryId": "<optional_repo_id>",
    "limit": 20
  }
}
```

- Check `status` (`running`, `completed`, `failed`, `canceled`, `interrupted`), `phase`, `startedAt`, `completedAt`, and `findingsCount`.
- A `failed`, `canceled`, or `interrupted` scan with zero findings is **not** a clean scan; always state the recorded terminal status and any retained scope limitations.
