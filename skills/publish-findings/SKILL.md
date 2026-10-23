---
name: agy-publish-findings
description: Import selected Snyk Open Source findings, Semgrep Code CLI/CI reports, Endor Labs findings, GitHub code-scanning alerts or GHSA advisories, or Wiz package vulnerabilities, SAST, repository secrets, and IaC findings locally into the AGY Security workbench after previewing the destination and evidence. Prefers native JSON; also supports Snyk plugin SCA bundles, Snyk Open Source and Semgrep Code SARIF, endorctl SARIF, saved GitHub JSON/JSONL, Wiz normalized JSONL and repository package-vulnerability CSV, and gzip; does not import workload secrets or cloud configuration, run a scan, assess findings, or synchronize triage decisions.
---

# AGY Publish Findings

Use the `import_agy_security_external_findings` and `list_agy_security_imported_findings` MCP tools (on `ServerName: "agy_security"`) for preview, local persistence, and readback. They own source mapping and local workbench SQLite persistence (`external_source_reports`). Do not implement another store or uploader or put credentials in a command argument.

## Choose the source report

Prefer the provider's supported native JSON from its authenticated CLI, plugin, or API. Keep the original records and complete the requested pagination. A JSON summary or a different product's API response is not interchangeable with the documented report. Use SARIF or CSV only when the installed provider reader supports that profile and native JSON is unavailable or the user supplies that format. Do not convert a richer JSON report to SARIF for import.

Use the same acquisition format for repeated imports. Check the provider's identity rules before switching formats: another format can create a separate record or replace a richer snapshot with less detail. Importing findings does not reconcile equivalent vulnerabilities across formats. Readers detect their supported inputs automatically.

## Local imports

For local storage, call `import_agy_security_external_findings` with `repositoryPath` and `dryRun: true` first to preview the selected evidence before importing:

```json
{
  "ServerName": "agy_security",
  "ToolName": "import_agy_security_external_findings",
  "Arguments": {
    "reportPath": "/path/to/selected-wiz-findings.json",
    "repositoryPath": "/path/to/project",
    "provider": "wiz",
    "sourceKey": "TENANT_ID/vulnerability-finding",
    "dryRun": true
  }
}
```

Show the repository, source namespace, normalized evidence, and exclusions. After confirmation, repeat with `dryRun: false`. Read the persisted result with `list_agy_security_imported_findings`:

```json
{
  "ServerName": "agy_security",
  "ToolName": "list_agy_security_imported_findings",
  "Arguments": {
    "repositoryPath": "/path/to/project"
  }
}
```

Local records remain unassessed source evidence, separate from `list_agy_security_findings` and completed scans. Retain unknown metadata without inventing scanner revisions, assessment fields, or patch results. Report the created, updated, unchanged, and excluded counts. Repeated imports use the same repository/provider/source-key/source-ID identity; omitted records remain stored. When a source repository URL and local Git remotes are available, the source URL must match one of those remotes. Local import does not automatically investigate or patch findings.

## Endor Labs findings

For Endor Labs imports, prefer native Finding JSON from authenticated `endorctl`, scoped to one project and context. Omit `--field-mask` and fetch all pages with `--list-all`:

```sh
endorctl api list --resource Finding --namespace "YOUR_NAMESPACE" \
  --filter 'context.type==CONTEXT_TYPE_MAIN and spec.project_uuid=="PROJECT_UUID"' \
  --list-all --output-type json > endor-findings.json
```

Then preview and import using `import_agy_security_external_findings` with `provider: "endor"`, `repositoryPath: "/path/to/project"`, and `sourceKey: "YOUR_NAMESPACE/PROJECT_UUID/main"`.

Choose a project that corresponds to the selected local checkout. For a different branch or scan context, change the Endor filter and keep a distinct, stable source key. The importer reads that saved file; it does not maintain an Endor API connection or write changes back to Endor.

Native JSON retains severity, scanned commit, package and advisory data, and primary SAST/AI SAST locations. Existing self-contained endorctl SARIF is a lossy compatibility format that retains finding UUIDs and links; unavailable severity or revisions stay unknown. Both formats use the Endor UUID within the selected repository and source key as identity. Importing SARIF after native JSON updates the same record by replacing its evidence snapshot, not merging it: native detail absent from SARIF is removed from that snapshot. Use native JSON consistently for ongoing imports. Keep the original evidence and inspect exclusions. Imported records remain unassessed source evidence.

## Wiz findings

Use an authorized Wiz MCP or Wiz API connection to acquire selected findings and save the supported native JSON with its original occurrence IDs and evidence. Inspect the returned fields: a summary, Wiz Issue, or local Wiz CLI scan result is not automatically a supported finding record. Do not invent fields to make a response fit the mapper.

Finish the requested pagination; for an explicit subset, retain that selection and its named collection. Prefer the supported native JSON. Normalized JSONL with `source_finding_id` and `evidence` and the documented repository package-vulnerability CSV profile are compatibility inputs; gzip is supported for each format. **CSV support covers repository package vulnerabilities (SCA) only, not SAST or cloud posture findings.** The tool does not fetch from Wiz or accept other CSV profiles, scan events, workload secrets, cloud configuration, or external network exports.

Use a stable Wiz tenant/finding namespace as `sourceKey`. A project filter is selection context, not a new identity. Confirm the selected assets or builds belong to the destination repository; do not infer a scanner branch or revision from the current checkout. Do not publish vendor credentials, unrelated records, or local assessments as original scanner evidence.

For an existing package vulnerability report or when a UI export is needed, use **Vulnerability Findings -> Save as -> Report**, keeping the repository and finding filters. Select **Repository Branch** (remove the default Virtual Machine selection), **JSON** or comma-separated **CSV**, and **Detailed** columns. Pass supported CSV reports directly to `import_agy_security_external_findings`; their GitHub `CloudProviderURL` must identify the destination repository branch. The importer retains every original cell in `source_data.row` and uses the reported `ID` as occurrence identity. Download the completed report; gzip compression is supported regardless of the filename extension.

For SAST, repository secrets, and IaC, retain the explicit `data.sastFindings.nodes`, `data.secretInstances.nodes`, or `data.iacFindings.nodes` collection. Bare arrays cannot identify these finding families. Include a verified URL on the source repository metadata or supply `data.versionControlResources.nodes` with matching `repository.id` and `repository.url`. Retain the documented inventory `platform` field; explicit `GITHUB` establishes case-insensitive matching on custom GitHub Enterprise hosts. Resolve conflicting platform or URL metadata for a repository ID before importing. For secrets, the repository is `resource.typedProperties.repository` and resource type must be `REPOSITORY_BRANCH`. Source URLs must match one of the configured local Git remotes. Resolve a missing or conflicting source mapping before importing.

Keep raw source records unchanged in `source_data`. New raw occurrence IDs are prefixed `sast:`, `secret:`, or `iac:`; existing package IDs are unchanged. Preserve rule/CWE, range/snippet, detector validation, and IaC comparison fields in the typed details. Preserve empty comparison strings. Do not invent missing IDs, severity, revisions, or locations, retrieve credential values, test credentials, or apply suggested fixes. Vendor status, AI verdict, secret validation, introduced commits, and logical IaC resources are evidence, not AGY Security assessment or proof of runtime deployment.

## Snyk Open Source

For CLI automation, prefer `snyk test --file=package.json --json-file-output=snyk-open-source.json` from the selected repository root. Exit 1 means vulnerabilities were found; stop on other nonzero exits instead of importing a stale file. Pass `provider: "snyk"` to `import_agy_security_external_findings`, which autodetects native JSON (one project or an `--all-projects` array), plugin JSON (`snyk-findings-export/v1`), and Open Source SARIF. Native JSON preserves per-dependency-path records and remediation fields; do not use `--group-issues`. Project errors stop import. Native JSON paths lack a Git-root offset and stay in original evidence. Only **Open Source SCA vulnerabilities** are imported: licenses, Code, Container, IaC, and platform backlog ingestion are outside this adapter.

Use one format consistently per repository, branch, and scan target, with a stable `sourceKey` such as `github.com/example/project/main/root/native-sca`. Plugin, native JSON, and SARIF have distinct identities; use separate keys when switching, without claiming cross-format deduplication or removal of older records. Existing `snyk test --sarif-file-output=snyk-open-source.sarif` reports remain a compatibility path.

Retain package versions, reported fixed versions, provenance, and original evidence without claiming a fix was applied. Known repository claims must match a configured local Git remote. Resolve an unknown repository with the user; never infer that an export belongs to the current checkout.

## Semgrep Code

Prefer native Code/SAST CLI or CI JSON for this reader; use self-contained SARIF 2.1.0 as a compatibility path. JSON retains the original severity better than SARIF. The reader does not accept Platform API, Guardian, or MCP response envelopes, or a general Supply Chain or Secrets feed. Select SAST rules or Code-only CI output; identifiable non-SAST records are excluded, but SARIF may omit the product metadata needed to distinguish Secrets.

For a user-requested new scan, use the installed Semgrep CLI from the source repository root with the selected SAST rules: `semgrep scan --config /path/to/sast-rules.yaml --json-output /path/to/semgrep.json .`. Existing CI jobs can produce the same artifact using `--json-output`. Explain that this generates fresh scan findings, and do not substitute it for a request to retrieve existing Platform findings.

Import the native report using `import_agy_security_external_findings` with `provider: "semgrep"`, a stable organization/project/branch `sourceKey`, and `sourceRepositoryUrl` identifying the actual source repository. Preview with `dryRun: true` before confirming the import.

Keep supplied fingerprints. Reimporting the same fingerprint after code moves updates the existing source record with the new range. If the fingerprint is absent or `requires login`, the fallback uses rule, literal path, and range: movement creates a second retained record, and the earlier record remains stored. Do not infer a merge or deletion. Read the persisted evidence with `list_agy_security_imported_findings` before assessment. Source rule, CWE, snippets, traces, and status are vendor evidence, not AGY Security assessments.

## GitHub alerts and advisories

Acquire code-scanning findings or GHSA advisories using `import_agy_security_external_findings` with `provider: "github"` on a saved `agy-security-github-code-scanning/v1`, `codex-security-github-code-scanning/v1`, `agy-security-github-advisories/v1`, or `codex-security-github-advisories/v1` JSON/JSONL file, or pass `githubRepository` (`OWNER/REPO`) directly to `import_agy_security_external_findings` to collect via authenticated `gh` CLI and import in one step.

**GHSA import stages advisory evidence for investigation; it does not establish an installed dependency or applicability to the destination repository.** Keep advisories separate from code scanning. Use separate stable `sourceKey` values for the two families (for example `github.com/example/project/code-scanning` and `github.com/example/project/security-advisories`). Code-scanning identities include the ref; repository alerts and advisories must match a configured local Git remote. Global advisories omit source-repository provenance and are bound to the explicit local destination for investigation. Preserve original evidence, package ranges, and patches; do not infer installed packages or source locations from an advisory. Missing security severity stays `unknown`. Dismissal, resolution, and withdrawal are source state, not AGY Security assessment.
