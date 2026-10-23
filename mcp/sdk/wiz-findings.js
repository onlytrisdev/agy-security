import { AgySecurityError } from "./errors.js";
import {
  repositoryUrlKey,
  validateExternalEvidence
} from "./external-import-contract.js";
import { parseJsonOrJsonl, readScannerText } from "./scanner-import.js";
import { readWizCsv, wizCsvFinding } from "./wiz-csv.js";

function object(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value
    : undefined;
}

function text(value) {
  return typeof value === "string" && value.trim() ? value : null;
}

function sourceFindingId(value) {
  const id = text(value);
  if (!id || id.includes("\0") || Buffer.byteLength(id) > 512) {
    throw new Error(
      "Source finding id must contain 1–512 UTF-8 bytes and no NUL characters."
    );
  }
  return id;
}

function wizFinding(record) {
  if (record["detectionMethod"] === "EXTERNAL_NETWORK_SCAN") {
    throw new Error(
      "Wiz external network findings are not supported by the package vulnerability mapping."
    );
  }
  const id = sourceFindingId(record["id"]);
  const name = text(record["name"]);
  const packageName = text(record["detailedName"]);
  const version = text(record["version"]);
  const severity = text(record["vendorSeverity"]) ?? text(record["severity"]);
  const asset = object(record["vulnerableAsset"]);
  const artifact = object(record["artifactType"]);
  if (!name || !packageName || !text(asset?.["id"])) {
    throw new Error(
      "Expected a Wiz package vulnerability finding with name, detailedName, and vulnerableAsset.id. Other finding classes need a separate mapping."
    );
  }
  const assetType = text(asset?.["type"]);
  const repositoryAsset =
    assetType === "REPOSITORY_BRANCH" ||
    asset?.["nativeType"] === "github#repositoryBranch";
  const locationPath = text(record["locationPath"]);
  const repositoryPath =
    repositoryAsset && locationPath ? locationPath.replace(/^\/+/, "") : null;
  const digest =
    text(asset?.["imageDigest"]) ??
    text(record["imageDigest"]) ??
    (assetType === null ||
    assetType === "CONTAINER_IMAGE" ||
    assetType === "CONTAINER"
      ? (text(asset?.["imageId"]) ??
        text(asset?.["containerImageId"]) ??
        text(asset?.["ImageExternalId"]))
      : null);
  const evidence = {
    title:
      text(record["title"]) ??
      [packageName, version, name].filter(Boolean).join(" "),
    description: text(record["description"]),
    severity: severity?.toLowerCase(),
    url: text(record["portalUrl"]),
    advisory_ids: [text(record["vulnerabilityExternalId"]) ?? name],
    packages: [
      {
        name: packageName,
        ecosystem:
          text(record["packageManager"]) ??
          text(artifact?.["osPackageManager"]) ??
          text(artifact?.["codeLibraryLanguage"]) ??
          text(record["codeLibraryLanguage"]),
        installed_version: version,
        manifest_path: repositoryPath,
        fixed_versions: text(record["fixedVersion"])
          ? [record["fixedVersion"]]
          : []
      }
    ],
    locations: repositoryPath ? [{ path: repositoryPath }] : [],
    branch: null,
    code_revision: null,
    source_scan_id: null,
    image_digests: digest ? [digest] : [],
    source_updated_at: updatedAt(record["updatedAt"], "updatedAt"),
    source_data: record
  };
  return {
    source_finding_id: id,
    evidence: validateExternalEvidence(evidence)
  };
}

function inventoryRepositoryUrlKey(value, platform) {
  const key = repositoryUrlKey(value);
  return platform === "GITHUB" ? key.toLowerCase() : key;
}

function sourceRepository(repository, repositories) {
  const id = text(repository?.["id"]);
  const inventory = id ? repositories.get(id) : undefined;
  const suppliedUrl = text(repository?.["url"]);
  if (
    suppliedUrl &&
    inventory &&
    inventoryRepositoryUrlKey(suppliedUrl, inventory.platform) !==
      inventoryRepositoryUrlKey(inventory.url, inventory.platform)
  ) {
    throw new Error(
      "The finding and repository inventory have conflicting repository URLs."
    );
  }
  const url = suppliedUrl ?? inventory?.url;
  if (!url) {
    throw new Error(
      "A verified source repository URL is required. Include repository.url or the matching repository.id and repository.url from data.versionControlResources.nodes; names and Wiz IDs are not repository IDs."
    );
  }
  return {
    id,
    name: text(repository?.["name"]) ?? inventory?.name ?? null,
    url
  };
}

function sourceBranch(branch, repository, legacy = false) {
  const name = text(branch?.["name"]);
  if (!name) {
    return null;
  }
  if (!legacy) {
    return name;
  }
  const qualifiers = repository.name ? [repository.name] : [];
  const repositoryKey = repositoryUrlKey(repository.url).toLowerCase();
  const url = /^(https?:\/\/[^/?#]+)\/([^?#]+)$/iu.exec(repositoryKey);
  if (url) {
    const prefixParts = url[2].split("/").length;
    const parts = name.split("/");
    const qualifier = parts.slice(0, prefixParts).join("/");
    if (
      parts.length > prefixParts &&
      repositoryUrlKey(url[1] + "/" + qualifier).toLowerCase() === repositoryKey
    ) {
      qualifiers.push(qualifier);
    }
  }
  for (const qualifier of qualifiers.sort(
    (left, right) => right.length - left.length
  )) {
    const prefix = qualifier + "/";
    if (name.toLowerCase().startsWith(prefix.toLowerCase())) {
      return name.slice(prefix.length) || null;
    }
  }
  return url || repository.name ? name : null;
}

function updatedAt(value, field) {
  const timestamp = text(value);
  if (!timestamp) {
    return null;
  }
  const seconds = Date.parse(timestamp) / 1000;
  if (!Number.isFinite(seconds) || seconds < 0) {
    throw new Error(`Wiz ${field} is not a valid timestamp.`);
  }
  return Math.floor(seconds);
}

function content(value) {
  return typeof value === "string" ? value : null;
}

function repositoryFinding(kind, record, repositories, legacy = false) {
  const id = sourceFindingId(record["id"]);
  const resource = object(record["resource"]);
  if (kind === "secret" && resource?.["type"] !== "REPOSITORY_BRANCH") {
    throw new Error(
      "Only repository-branch secret findings can be published to a repository. Workload secrets require a resource-scoped import and are not supported."
    );
  }
  const suppliedRepository =
    kind === "secret"
      ? object(object(resource?.["typedProperties"])?.["repository"])
      : object(record["repository"]);
  const repository = sourceRepository(suppliedRepository, repositories);
  const branch =
    kind === "secret"
      ? resource
      : object(record[kind === "sast" ? "repositoryBranch" : "branch"]);
  const rule = object(record["rule"]);
  const path = text(record[kind === "secret" ? "path" : "filePath"]);
  const line = record[kind === "secret" ? "lineNumber" : "startLine"];
  const details = {
    kind,
    repository,
    source_status: text(record["status"]),
    scanner_origin: kind === "sast" ? text(record["origin"]) : null,
    scanner_verdict:
      kind === "sast" ? text(object(record["aiAnalysis"])?.["verdict"]) : null,
    rule: rule
      ? {
          id: text(rule["id"]),
          short_id: text(rule["shortId"]),
          name: text(rule["name"])
        }
      : null,
    weakness_ids:
      kind === "sast" && Array.isArray(record["weaknesses"])
        ? record["weaknesses"].map((weakness) => object(weakness)?.["id"])
        : [],
    remediation_instructions:
      text(record["remediationInstructions"]) ??
      text(rule?.["remediationInstructions"]),
    code:
      path && kind !== "secret"
        ? {
            end_line: record["endLine"] ?? null,
            snippet: content(
              record[kind === "sast" ? "snippet" : "matchContent"]
            )
          }
        : null,
    secret:
      kind === "secret"
        ? {
            type: text(record["type"]),
            confidence: text(record["confidence"]),
            validation_status: text(record["validationStatus"]),
            is_encrypted: record["isEncrypted"] ?? null,
            is_managed: record["isManaged"] ?? null,
            introduced_commit: text(
              object(record["vcsDetails"])?.["initialCommitHash"]
            )
          }
        : null,
    configuration:
      kind === "iac"
        ? {
            platform: text(record["platform"]),
            cloud_platform: text(record["cloudPlatform"]),
            expected: content(record["expectedContent"]),
            actual: content(record["foundContent"])
          }
        : null,
    file_url: text(record["fileURL"])
  };
  return {
    source_finding_id: sourceFindingId(`${kind}:${id}`),
    evidence: validateExternalEvidence({
      title: text(record["name"]) ?? text(rule?.["name"]),
      severity: text(record["severity"])?.toLowerCase(),
      description: text(record["description"]) ?? text(rule?.["description"]),
      url: text(record["wizUrl"]) ?? text(record["portalUrl"]),
      locations: path ? [{ path, line: line ?? null }] : [],
      branch: sourceBranch(branch, repository, legacy),
      code_revision: null,
      source_scan_id: null,
      source_updated_at:
        kind === "secret"
          ? updatedAt(record["lastUpdatedAt"], "lastUpdatedAt")
          : kind === "iac"
            ? updatedAt(record["updatedAt"], "updatedAt")
            : null,
      source_data: record,
      details
    })
  };
}

function records(payload) {
  const repositories = new Map();
  const legacyRepositories = new Map();
  if (Array.isArray(payload)) {
    return { records: payload.map((value) => ({ value })), repositories };
  }
  const envelope = object(payload);
  if (!envelope) {
    throw new Error(
      "Expected finding objects or a named Wiz finding collection."
    );
  }
  if (
    object(envelope["scannersRunStatuses"]) &&
    object(envelope["codeAnalyzerDetails"])
  ) {
    throw new Error(
      "This is a Wiz Code & Build Scan event, which contains scan metadata rather than vulnerability records. In Vulnerability Findings, filter the repository and selection, then choose Save as -> Report with JSON format and Detailed columns. Download that report instead of Raw Event."
    );
  }
  if (Array.isArray(envelope["errors"]) && envelope["errors"].length > 0) {
    throw new Error(
      "Wiz returned GraphQL errors. Resolve them before publishing this response."
    );
  }
  if (
    envelope["source_finding_id"] !== undefined ||
    envelope["id"] !== undefined
  ) {
    return { records: [{ value: envelope }], repositories };
  }
  const data = object(envelope["data"]) ?? envelope;
  const inventory = object(data["versionControlResources"]);
  if (object(inventory?.["pageInfo"])?.["hasNextPage"] === true) {
    throw new Error(
      "Wiz repository inventory has another page. Finish the selected inventory before publishing."
    );
  }
  if (Array.isArray(inventory?.["nodes"])) {
    const entries = inventory["nodes"].flatMap((entry) => {
      const node = object(entry);
      const repository = object(node?.["repository"]);
      const id = text(repository?.["id"]);
      const url = text(repository?.["url"]);
      return id && url
        ? [
            {
              id,
              name: text(repository?.["name"]),
              url,
              platform: text(node?.["platform"])
            }
          ]
        : [];
    });
    for (const entry of entries) {
      const previous = repositories.get(entry.id);
      if (
        previous?.platform &&
        entry.platform &&
        previous.platform !== entry.platform
      ) {
        throw new Error(
          `Repository inventory contains conflicting platforms for ${JSON.stringify(entry.id)}.`
        );
      }
      repositories.set(entry.id, {
        ...entry,
        url: previous && previous.url < entry.url ? previous.url : entry.url,
        name:
          previous?.name && (!entry.name || previous.name < entry.name)
            ? previous.name
            : entry.name,
        platform: entry.platform ?? previous?.platform ?? null
      });
      legacyRepositories.set(entry.id, {
        ...entry,
        platform: entry.platform ?? previous?.platform ?? null
      });
    }
    for (const entry of entries) {
      const resolved = repositories.get(entry.id);
      if (
        inventoryRepositoryUrlKey(entry.url, resolved.platform) !==
        inventoryRepositoryUrlKey(resolved.url, resolved.platform)
      ) {
        throw new Error(
          `Repository inventory contains conflicting URLs for ${JSON.stringify(entry.id)}.`
        );
      }
    }
  }
  const collections = {
    vulnerabilityFindings: "sca",
    sastFindings: "sast",
    secretInstances: "secret",
    iacFindings: "iac",
    configurationFindings: "cloud_configuration"
  };
  const selected = [];
  let found = false;
  for (const [root, kind] of Object.entries(collections)) {
    const collection = object(data[root]);
    if (!collection) {
      continue;
    }
    found = true;
    if (!Array.isArray(collection["nodes"])) {
      throw new Error(`Wiz ${root}.nodes must be an array.`);
    }
    if (object(collection["pageInfo"])?.["hasNextPage"] === true) {
      throw new Error(
        "Wiz response has another page. Complete the requested pages or save the explicitly selected records in their named collection before publishing."
      );
    }
    for (const value of collection["nodes"]) {
      selected.push({ value, kind });
    }
  }
  if (found) {
    return {
      records: selected,
      repositories,
      legacyRepositories
    };
  }
  throw new Error(
    "Unsupported Wiz export. Supply repository vulnerability CSV, vulnerability finding objects, named sastFindings/secretInstances/iacFindings collections, or normalized JSONL. Other CSV reports need an explicit normalized JSONL mapping."
  );
}

export async function readVendorFindings(path) {
  return normalizeFindings(await readFindingInput(path));
}

export async function readVendorFindingsForPublication(path) {
  const input = await readFindingInput(path);
  const normalized = new WeakSet();
  const current = normalizeFindings(input, normalized);
  const legacy = normalizeFindings(
    {
      ...input,
      repositories: input.legacyRepositories ?? input.repositories
    },
    normalized,
    true
  );
  const identity = (parsed) =>
    parsed.findings.map((finding) => {
      if (normalized.has(finding)) {
        return finding;
      }
      const repository = finding.evidence.details?.repository;
      return {
        source_finding_id: finding.source_finding_id,
        evidence: {
          source_data: finding.evidence.source_data,
          repository: repository
            ? {
                id: repository.id,
                url: repositoryUrlKey(repository.url).toLowerCase()
              }
            : null
        }
      };
    });
  return {
    current,
    legacy,
    currentIdentity: identity(current),
    legacyIdentity: identity(legacy),
    sourceRepositories: current.findings.flatMap(({ evidence }) => {
      const repository = evidence.details?.repository;
      const inventory = input.repositories.get(repository?.id ?? "");
      return repository &&
        inventory?.platform === "GITHUB" &&
        inventoryRepositoryUrlKey(repository.url, inventory.platform) ===
          inventoryRepositoryUrlKey(inventory.url, inventory.platform)
        ? [{ url: repository.url, platform: "github" }]
        : [];
    })
  };
}

async function readFindingInput(path) {
  try {
    const contents = await readScannerText(path);
    let payload;
    try {
      payload = JSON.parse(contents);
    } catch {
      const csv = readWizCsv(contents);
      if (csv) {
        return {
          records: csv.map((value) => ({ value, kind: "sca_csv" })),
          repositories: new Map()
        };
      }
      payload = parseJsonOrJsonl(contents);
    }
    return records(payload);
  } catch (cause) {
    throw new AgySecurityError(
      `Could not read vendor findings as UTF-8 JSON, JSONL, or Wiz CSV: ${cause instanceof Error ? cause.message : String(cause)}`,
      { cause }
    );
  }
}

function normalizeFindings(input, normalized, legacy = false) {
  const result = {
    read: input.records.length,
    findings: [],
    excluded: []
  };
  const identities = new Set();
  for (const [index, item] of input.records.entries()) {
    const record = object(item.value);
    try {
      if (!record) {
        throw new Error("Finding must be an object.");
      }
      let finding;
      if (item.kind === "sca_csv") {
        finding = wizCsvFinding(record, sourceFindingId(record["ID"]));
      } else if ("source_finding_id" in record) {
        if (
          Object.keys(record).some(
            (key) => !["source_finding_id", "evidence"].includes(key)
          )
        ) {
          throw new Error(
            "Normalized input permits only source_finding_id and evidence."
          );
        }
        finding = {
          source_finding_id: sourceFindingId(record["source_finding_id"]),
          evidence: validateExternalEvidence(record["evidence"])
        };
      } else if (item.kind === "cloud_configuration") {
        throw new Error(
          "Cloud configuration findings require a resource-scoped import and cannot be published to a repository."
        );
      } else if (item.kind && item.kind !== "sca") {
        finding = repositoryFinding(
          item.kind,
          record,
          input.repositories,
          legacy
        );
      } else {
        if (
          !item.kind &&
          (object(record["repository"]) ||
            object(record["repositoryBranch"]) ||
            object(record["resource"]))
        ) {
          throw new Error(
            "Raw SAST, secret, and IaC records require their named sastFindings, secretInstances, or iacFindings collection. Bare arrays do not identify the finding family; use normalized JSONL for an explicit mapping."
          );
        }
        finding = wizFinding(record);
      }
      if (identities.has(finding.source_finding_id)) {
        throw new AgySecurityError(
          `Duplicate source finding id ${JSON.stringify(finding.source_finding_id)}. Select each vendor occurrence once.`
        );
      }
      identities.add(finding.source_finding_id);
      result.findings.push(finding);
      if (item.kind !== "sca_csv" && "source_finding_id" in record) {
        normalized?.add(finding);
      }
    } catch (error) {
      if (error instanceof AgySecurityError) {
        throw error;
      }
      result.excluded.push({
        position: index + 1,
        source_finding_id:
          item.kind === "sca_csv"
            ? text(record?.["ID"])
            : (text(record?.["source_finding_id"]) ?? text(record?.["id"])),
        reason: error instanceof Error ? error.message : String(error)
      });
    }
  }
  return result;
}
