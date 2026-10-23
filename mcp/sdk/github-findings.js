import { hash } from "node:crypto";
import { AgySecurityError, errorMessage } from "./errors.js";
import { validateExternalEvidence } from "./external-import-contract.js";
import { parseJsonOrJsonl, readScannerText, text } from "./scanner-import.js";

function object(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value
    : undefined;
}

function repositoryName(value) {
  const repository = text(value);
  const parts = /^([a-z0-9_.-]+)\/([a-z0-9_.-]+)$/iu.exec(repository ?? "");
  if (!parts || parts.slice(1).some((part) => /^\.{1,2}$/u.test(part))) {
    throw new Error("GitHub repository must be OWNER/REPO.");
  }
  return repository;
}

function sourceUrl(value) {
  const parsed = new URL(value);
  const origin = /^(https?:\/\/([^/?#]+))/iu.exec(value);
  if (!origin) {
    throw new Error("GitHub evidence URL must be an HTTP(S) link.");
  }
  return { parsed, host: origin[2].toLowerCase(), origin: origin[1] };
}

function sourceTimestamp(value) {
  if (value === undefined || value === null) {
    return null;
  }
  const seconds = typeof value === "string" ? Date.parse(value) / 1000 : NaN;
  if (!Number.isFinite(seconds) || seconds < 0) {
    throw new Error("GitHub updated_at is not a valid timestamp.");
  }
  return Math.floor(seconds);
}

function severity(value) {
  return typeof value === "string" &&
    ["critical", "high", "medium", "low", "informational"].includes(value)
    ? value
    : "unknown";
}

function codeScanningFinding(record) {
  const repository = repositoryName(record["repository"]);
  const alert = object(record["alert"]);
  const number = record["number"];
  if (
    !alert ||
    typeof number !== "number" ||
    !Number.isSafeInteger(number) ||
    number < 1 ||
    alert["number"] !== number
  ) {
    throw new Error(
      "Expected a GitHub code-scanning import with matching alert numbers."
    );
  }
  const url = text(record["url"]);
  if (!url || url !== alert["html_url"]) {
    throw new Error("GitHub alert URL must match the original alert.");
  }
  const { parsed: parsedUrl, host, origin } = sourceUrl(url);
  if (
    !["security/code-scanning", "code-scanning"].some(
      (route) =>
        parsedUrl.pathname.toLowerCase() ===
        `/${repository}/${route}/${number}`.toLowerCase()
    )
  ) {
    throw new Error(
      "GitHub alert URL does not match the selected repository and alert."
    );
  }
  const rule = object(alert["rule"]);
  const instance = object(alert["most_recent_instance"]);
  const ref = text(instance?.["ref"]);
  if (!ref) {
    throw new Error(
      "GitHub code-scanning evidence requires the selected instance ref."
    );
  }
  const location = object(instance?.["location"]);
  const tool = object(alert["tool"]);
  const message = text(object(instance?.["message"])?.["text"]);
  const description =
    text(rule?.["full_description"]) ?? text(rule?.["description"]);
  const tags = Array.isArray(rule?.["tags"]) ? rule["tags"] : [];
  const weaknessIds = [
    ...new Set(
      tags.flatMap((tag) => {
        const match =
          typeof tag === "string"
            ? /^external\/cwe\/cwe-(\d+)$/iu.exec(tag)
            : null;
        return match ? [`CWE-${Number(match[1])}`] : [];
      })
    )
  ];
  const path = text(location?.["path"]);
  const sourceId = `${host}/${repository.toLowerCase()}/code-scanning/${number}/${hash("sha256", ref)}`;
  return {
    source_finding_id: sourceId,
    evidence: validateExternalEvidence({
      title:
        text(rule?.["name"]) ??
        text(rule?.["description"]) ??
        `GitHub code-scanning alert #${number}`,
      severity: severity(rule?.["security_severity_level"]),
      description:
        [...new Set([message, description].filter(Boolean))].join("\n\n") ||
        null,
      url,
      locations: path ? [{ path, line: location?.["start_line"] ?? null }] : [],
      branch: ref,
      code_revision: text(instance?.["commit_sha"]),
      source_updated_at: sourceTimestamp(alert["updated_at"]),
      source_data: record,
      details: {
        kind: "sast",
        repository: {
          url: `${origin}/${repository}`,
          name: repository
        },
        source_status:
          alert["state"] === "dismissed"
            ? "dismissed"
            : (text(instance?.["state"]) ?? text(alert["state"])),
        scanner_origin: text(tool?.["name"]),
        rule: { id: text(rule?.["id"]), name: text(rule?.["name"]) },
        weakness_ids: weaknessIds,
        remediation_instructions: text(rule?.["help"]),
        code: path ? { end_line: location?.["end_line"] ?? null } : null
      }
    })
  };
}

function advisoryFinding(record) {
  const repository = repositoryName(record["repository"]);
  const advisory = object(record["advisory"]);
  const id = text(record["ghsaId"]);
  const selection = record["selection"];
  if (
    !advisory ||
    !id ||
    !/^GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/iu.test(id) ||
    text(advisory["ghsa_id"])?.toUpperCase() !== id.toUpperCase()
  ) {
    throw new Error(
      "Expected a GitHub advisory import with matching GHSA IDs."
    );
  }
  if (selection !== "repository" && selection !== "global") {
    throw new Error("GitHub advisory selection must be repository or global.");
  }
  const url = text(record["url"]);
  if (!url || url !== advisory["html_url"]) {
    throw new Error("GitHub advisory URL must match the original advisory.");
  }
  const { parsed: parsedUrl, host: linkHost, origin } = sourceUrl(url);
  const host = text(record["githubHost"])?.toLowerCase();
  const canonicalGlobalLink =
    selection === "global" && parsedUrl.host === "github.com";
  const expectedPath =
    selection === "repository"
      ? `/${repository}/security/advisories/${id}`
      : `/advisories/${id}`;
  if (
    !host ||
    (linkHost !== host && !canonicalGlobalLink) ||
    parsedUrl.pathname.toLowerCase() !== expectedPath.toLowerCase()
  ) {
    throw new Error(
      "GitHub advisory URL does not match the selected source and GHSA ID."
    );
  }
  const vulnerabilities =
    advisory["vulnerabilities"] === null ? [] : advisory["vulnerabilities"];
  if (!Array.isArray(vulnerabilities)) {
    throw new Error("GitHub advisory vulnerabilities must be an array.");
  }
  const identifiers = Array.isArray(advisory["identifiers"])
    ? advisory["identifiers"]
    : [];
  const advisoryIds = [
    id,
    text(advisory["cve_id"]),
    ...identifiers.map((identifier) => text(object(identifier)?.["value"]))
  ].filter((value) => value !== null);
  const packages = vulnerabilities.flatMap((value) => {
    const vulnerability = object(value);
    const pkg = object(vulnerability?.["package"]);
    const name = text(pkg?.["name"]);
    if (!name) {
      return [];
    }
    const fixedVersion =
      text(vulnerability?.["first_patched_version"]) ??
      text(vulnerability?.["patched_versions"]);
    return [
      {
        name,
        ecosystem: text(pkg?.["ecosystem"]),
        vulnerable_version_range: text(
          vulnerability?.["vulnerable_version_range"]
        ),
        fixed_versions: fixedVersion ? [fixedVersion] : []
      }
    ];
  });
  const cwes = Array.isArray(advisory["cwes"]) ? advisory["cwes"] : [];
  return {
    source_finding_id: `${host}/${selection === "repository" ? repository.toLowerCase() : "global"}/security-advisory/${id.toUpperCase()}`,
    evidence: validateExternalEvidence({
      title: text(advisory["summary"]) ?? id,
      severity: severity(advisory["severity"]),
      description: text(advisory["description"]),
      url,
      advisory_ids: [...new Set(advisoryIds)],
      packages,
      source_updated_at: sourceTimestamp(advisory["updated_at"]),
      source_data: record,
      details: {
        kind: "advisory",
        advisory: { source: selection },
        ...(selection === "repository"
          ? {
              repository: {
                url: `${origin}/${repository}`,
                name: repository
              }
            }
          : {}),
        source_status: text(advisory["withdrawn_at"])
          ? "withdrawn"
          : (text(advisory["state"]) ??
            (selection === "global" ? "published" : null)),
        scanner_origin: "GitHub Security Advisories",
        weakness_ids: cwes
          .map((value) => text(object(value)?.["cwe_id"]))
          .filter((value) => value !== null)
      }
    })
  };
}

function normalizeRecords(records) {
  const result = {
    read: records.length,
    findings: [],
    excluded: []
  };
  const identities = new Set();
  for (const [index, value] of records.entries()) {
    const record = object(value);
    try {
      if (!record) {
        throw new Error("GitHub finding must be an object.");
      }
      let finding;
      if (record["source"] === "github-code-scanning") {
        finding = codeScanningFinding(record);
      } else if (record["source"] === "github-security-advisory") {
        finding = advisoryFinding(record);
      } else {
        throw new Error(
          "Expected saved output from import github or import github-advisories; raw or incomplete API responses need an explicit mapping."
        );
      }
      if (identities.has(finding.source_finding_id)) {
        throw new AgySecurityError(
          `Duplicate source finding id ${JSON.stringify(finding.source_finding_id)}. Select each GitHub occurrence once.`
        );
      }
      identities.add(finding.source_finding_id);
      result.findings.push(finding);
    } catch (error) {
      if (error instanceof AgySecurityError) {
        throw error;
      }
      result.excluded.push({
        position: index + 1,
        source_finding_id: text(record?.["url"]),
        reason: errorMessage(error)
      });
    }
  }
  return result;
}

export function normalizeGitHubCodeScanningAlerts(alerts) {
  return normalizeRecords(alerts);
}

export function normalizeGitHubAdvisories(advisories) {
  return normalizeRecords(advisories);
}

export async function readGitHubFindings(path) {
  try {
    const payload = parseJsonOrJsonl(await readScannerText(path));
    return normalizeRecords(Array.isArray(payload) ? payload : [payload]);
  } catch (cause) {
    throw new AgySecurityError(
      `Could not read GitHub findings as UTF-8 JSON or JSONL: ${errorMessage(cause)}`,
      { cause }
    );
  }
}
