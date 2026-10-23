import { hash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";
import { gunzip } from "node:zlib";
import { AgySecurityError, errorMessage } from "./errors.js";
import { isRecord } from "./record.js";

export function record(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object.`);
  }
  return value;
}

export function array(value, label) {
  if (!Array.isArray(value)) {
    throw new Error(`${label} must be an array.`);
  }
  return value;
}

export function text(value) {
  return typeof value === "string" && value.trim() ? value : null;
}

export function requiredText(value, label) {
  const result = text(value);
  if (!result) {
    throw new Error(`${label} must be nonempty text.`);
  }
  return result;
}

export function strings(value) {
  return Array.isArray(value)
    ? value.filter((v) => text(v) !== null)
    : [];
}

export function relativePath(value) {
  const path = text(value)?.replaceAll("\\", "/");
  return path &&
    !path.startsWith("/") &&
    !path.includes("\0") &&
    !/^[A-Za-z]:/.test(path) &&
    !path.split("/").includes("..")
    ? path
    : null;
}

export function stableId(prefix, fields) {
  return `${prefix}:${hash("sha256", JSON.stringify(fields))}`;
}

export async function readScannerText(path) {
  let bytes = await readFile(path);
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
    bytes = await promisify(gunzip)(bytes);
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

export function parseJsonOrJsonl(contents) {
  try {
    return JSON.parse(contents);
  } catch {
    return contents
      .split(/\r?\n/u)
      .filter((line) => line.trim())
      .map((line) => JSON.parse(line));
  }
}

export async function readScannerJson(path) {
  let bytes = await readFile(path);
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
    bytes = await promisify(gunzip)(bytes);
  }
  let decoded;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    throw new AgySecurityError(
      `Scanner report is not valid UTF-8. ${errorMessage(error)}`,
      { cause: error }
    );
  }
  try {
    return JSON.parse(decoded.replace(/^\uFEFF/u, ""));
  } catch (error) {
    throw new AgySecurityError(
      `Scanner JSON could not be parsed. ${errorMessage(error)}`,
      { cause: error }
    );
  }
}

export function hasSarifExternalPropertyReferences(value) {
  if (value == null) {
    return false;
  }
  return Object.entries(record(value, "SARIF external property references")).some(
    ([key, references]) =>
      key !== "properties" &&
      (!Array.isArray(references) || references.length > 0)
  );
}

const sarifArtifactLocationFields = new Set([
  "artifactLocation",
  "analysisTarget",
  "executableLocation",
  "workingDirectory",
  "stdin",
  "stdout",
  "stderr",
  "stdoutStderr",
  "mappedTo",
  "displayBase"
]);

export function sarifRunContextForResult(runContext, ...selectedEvidence) {
  const { artifacts, ...context } = runContext;
  if (!Array.isArray(artifacts) || artifacts.length === 0) {
    return runContext;
  }
  const locations = [];
  let hasArtifactLink = false;
  function visit(value) {
    if (typeof value === "string") {
      if (/sarif:/iu.test(value)) {
        hasArtifactLink = true;
      }
    } else if (Array.isArray(value)) {
      value.forEach(visit);
    } else if (isRecord(value)) {
      for (const [key, child] of Object.entries(value)) {
        if (key === "properties") {
          continue;
        }
        if (sarifArtifactLocationFields.has(key) && isRecord(child)) {
          locations.push(child);
        }
        if (
          ["locations", "responseFiles", "analysisToolLogFiles"].includes(key) &&
          Array.isArray(child)
        ) {
          locations.push(...child.filter(isRecord));
        }
        if (key === "originalUriBaseIds" && isRecord(child)) {
          locations.push(...Object.values(child).filter(isRecord));
        }
        visit(child);
      }
    }
  }
  visit([context, ...selectedEvidence]);
  if (hasArtifactLink) {
    return runContext;
  }
  const unresolvedUri = /[%:\\]|(?:^|\/)\.\.?(?:\/|$)/u;
  for (const location of locations) {
    if (typeof location["index"] === "number" && location["index"] >= 0) {
      return runContext;
    }
    if (typeof location["uri"] !== "string") {
      continue;
    }
    for (const artifact of artifacts) {
      if (!isRecord(artifact) || !isRecord(artifact["location"])) {
        continue;
      }
      const candidate = artifact["location"];
      if (
        location["uriBaseId"] !== candidate["uriBaseId"] ||
        unresolvedUri.test(location["uri"]) ||
        (typeof candidate["uri"] === "string" &&
          unresolvedUri.test(candidate["uri"])) ||
        location["uri"] === candidate["uri"]
      ) {
        return runContext;
      }
    }
  }
  return context;
}

export function normalizeRecords(records, normalize, identify) {
  const result = {
    read: records.length,
    findings: [],
    excluded: []
  };
  const identified = [];
  const counts = new Map();
  for (const [index, value] of records.entries()) {
    try {
      const id = identify(value);
      if (!id.trim() || id.includes("\0") || Buffer.byteLength(id) > 512) {
        throw new Error(
          "Source finding ID must contain 1–512 UTF-8 bytes and no NUL characters."
        );
      }
      identified.push({ position: index + 1, value, id });
      counts.set(id, (counts.get(id) ?? 0) + 1);
    } catch (error) {
      result.excluded.push({
        position: index + 1,
        source_finding_id: null,
        reason: errorMessage(error)
      });
    }
  }
  for (const { position, value, id } of identified) {
    if (counts.get(id) > 1) {
      result.excluded.push({
        position,
        source_finding_id: id,
        reason:
          "Ambiguous duplicate source identity; select one complete finding or separate source projects."
      });
      continue;
    }
    try {
      const finding = normalize(value, id);
      if (finding.source_finding_id !== id) {
        throw new Error("Finding identity changed during normalization.");
      }
      result.findings.push(finding);
    } catch (error) {
      result.excluded.push({
        position,
        source_finding_id: id,
        reason: errorMessage(error)
      });
    }
  }
  result.excluded.sort((a, b) => a.position - b.position);
  return result;
}
