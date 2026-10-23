import { readFileSync } from "node:fs";
import { isIP } from "node:net";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { AgySecurityError } from "./errors.js";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

const STRING_BYTE_LIMITS = {
  description: 65536,
  snippet: 65536,
  remediation_instructions: 65536,
  expected: 65536,
  actual: 65536,
  file_url: 2048,
  path: 2048,
  url: 2048,
  manifest_path: 2048,
  client_id: 128,
  next: 4096
};

let cachedRootSchema = null;

function loadRootSchema() {
  if (cachedRootSchema !== null) {
    return cachedRootSchema;
  }
  const currentDirectory = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    resolve(currentDirectory, "../../schemas/external-findings.schema.json"),
    resolve(currentDirectory, "../schemas/external-findings.schema.json")
  ];
  for (const candidate of candidates) {
    try {
      cachedRootSchema = JSON.parse(readFileSync(candidate, "utf8"));
      return cachedRootSchema;
    } catch {
      // Try next candidate
    }
  }
  throw new AgySecurityError("External finding contract schema could not be found.");
}

function resolveRef(rootSchema, ref) {
  if (!ref.startsWith("#/$defs/")) {
    throw new AgySecurityError(`Unsupported schema $ref: ${ref}`);
  }
  const defName = ref.slice("#/$defs/".length);
  const target = rootSchema.$defs?.[defName];
  if (!target) {
    throw new AgySecurityError(`Missing schema definition: ${defName}`);
  }
  return target;
}

function cloneDefault(val) {
  if (val === null || typeof val !== "object") {
    return val;
  }
  return structuredClone(val);
}

function codePointLength(str) {
  return Array.from(str).length;
}

function validateNode(rootSchema, schemaNode, value, instancePath, applyDefaults = true) {
  const schema = schemaNode.$ref ? resolveRef(rootSchema, schemaNode.$ref) : schemaNode;

  if (schema.anyOf) {
    let firstError = null;
    for (const branch of schema.anyOf) {
      const resolvedBranch = branch.$ref ? resolveRef(rootSchema, branch.$ref) : branch;
      if (resolvedBranch.type === "null") {
        if (value === null) {
          return null;
        }
        continue;
      }
      const err = validateNode(rootSchema, branch, value, instancePath, applyDefaults);
      if (err === null) {
        return null;
      }
      firstError ??= err;
    }
    return firstError ?? `${instancePath || "/"} does not match any allowed schema`;
  }

  if (schema.const !== undefined) {
    if (value !== schema.const) {
      return `${instancePath || "/"} must be equal to constant ${JSON.stringify(schema.const)}`;
    }
  }

  if (schema.enum !== undefined) {
    if (!schema.enum.includes(value)) {
      return `${instancePath || "/"} must be equal to one of the allowed values`;
    }
  }

  if (schema.type === "null") {
    return value === null ? null : `${instancePath || "/"} must be null`;
  }

  if (schema.type === "boolean") {
    return typeof value === "boolean" ? null : `${instancePath || "/"} must be boolean`;
  }

  if (schema.type === "integer") {
    if (typeof value !== "number" || !Number.isInteger(value)) {
      return `${instancePath || "/"} must be integer`;
    }
    if (schema.minimum !== undefined && value < schema.minimum) {
      return `${instancePath || "/"} must be >= ${schema.minimum}`;
    }
    if (schema.maximum !== undefined && value > schema.maximum) {
      return `${instancePath || "/"} must be <= ${schema.maximum}`;
    }
    return null;
  }

  if (schema.type === "number") {
    if (typeof value !== "number" || !Number.isFinite(value)) {
      return `${instancePath || "/"} must be number`;
    }
    if (schema.minimum !== undefined && value < schema.minimum) {
      return `${instancePath || "/"} must be >= ${schema.minimum}`;
    }
    if (schema.maximum !== undefined && value > schema.maximum) {
      return `${instancePath || "/"} must be <= ${schema.maximum}`;
    }
    return null;
  }

  if (schema.type === "string") {
    if (typeof value !== "string") {
      return `${instancePath || "/"} must be string`;
    }
    const len = codePointLength(value);
    if (schema.minLength !== undefined && len < schema.minLength) {
      return `${instancePath || "/"} must NOT have fewer than ${schema.minLength} characters`;
    }
    if (schema.maxLength !== undefined && len > schema.maxLength) {
      return `${instancePath || "/"} must NOT have more than ${schema.maxLength} characters`;
    }
    if (schema.pattern !== undefined) {
      const regex = new RegExp(schema.pattern, "u");
      if (!regex.test(value)) {
        return `${instancePath || "/"} must match pattern "${schema.pattern}"`;
      }
    }
    if (schema.format === "uuid" && !UUID_PATTERN.test(value)) {
      return `${instancePath || "/"} must match format "uuid"`;
    }
    return null;
  }

  if (schema.type === "array") {
    if (!Array.isArray(value)) {
      return `${instancePath || "/"} must be array`;
    }
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      return `${instancePath || "/"} must NOT have fewer than ${schema.minItems} items`;
    }
    if (schema.maxItems !== undefined && value.length > schema.maxItems) {
      return `${instancePath || "/"} must NOT have more than ${schema.maxItems} items`;
    }
    if (schema.items) {
      for (let i = 0; i < value.length; i++) {
        const err = validateNode(rootSchema, schema.items, value[i], `${instancePath}/${i}`, applyDefaults);
        if (err !== null) {
          return err;
        }
      }
    }
    return null;
  }

  if (schema.type === "object") {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      return `${instancePath || "/"} must be object`;
    }
    const props = schema.properties ?? {};
    if (applyDefaults) {
      for (const [propName, propSchema] of Object.entries(props)) {
        if (value[propName] === undefined) {
          if (propSchema.default !== undefined) {
            value[propName] = cloneDefault(propSchema.default);
          } else if (propSchema.$ref) {
            const target = resolveRef(rootSchema, propSchema.$ref);
            if (
              target.type === "object" &&
              (!target.required || target.required.length === 0) &&
              Object.values(target.properties ?? {}).some((p) => p.default !== undefined)
            ) {
              value[propName] = {};
            }
          }
        }
      }
    }
    if (schema.required) {
      for (const reqKey of schema.required) {
        if (value[reqKey] === undefined) {
          return `${instancePath || "/"} must have required property '${reqKey}'`;
        }
      }
    }
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        if (!Object.hasOwn(props, key)) {
          return `${instancePath || "/"} must NOT have additional properties ('${key}')`;
        }
      }
    }
    for (const [propName, propSchema] of Object.entries(props)) {
      if (value[propName] !== undefined) {
        const err = validateNode(
          rootSchema,
          propSchema,
          value[propName],
          `${instancePath}/${propName}`,
          applyDefaults
        );
        if (err !== null) {
          return err;
        }
      }
    }
    return null;
  }

  return null;
}

export function repositoryUrlKey(value) {
  const normalized = value.replace(/\/$/u, "").replace(/\.git$/u, "");
  const parts = /^(https?):\/\/([^/?#]+)((?:\/[^?#]*)?)((?:[?#].*)?)$/iu.exec(normalized);
  if (!parts) {
    return normalized;
  }
  const authority = parts[2].toLowerCase();
  const hostname = authority.replace(/:\d+$/u, "");
  const path =
    hostname === "github.com" || hostname.endsWith(".ghe.com")
      ? parts[3].toLowerCase()
      : parts[3];
  return `${parts[1].toLowerCase()}://${authority}${path}${parts[4]}`;
}

export function cloudRepositoryUrlKey(value) {
  return repositoryUrlKey(value).toLowerCase();
}

function validateModelStrings(input) {
  if (input === null || typeof input !== "object") {
    return;
  }
  if (Array.isArray(input)) {
    for (const item of input) {
      validateModelStrings(item);
    }
    return;
  }
  for (const [field, value] of Object.entries(input)) {
    if (field === "source_data") {
      continue;
    }
    if (typeof value === "string") {
      if (
        (!value.trim() && !["snippet", "expected", "actual"].includes(field)) ||
        value.includes("\0")
      ) {
        throw new Error(`${field} must be nonempty and contain no NUL characters.`);
      }
      const limit = STRING_BYTE_LIMITS[field] ?? 512;
      if (Buffer.byteLength(value) > limit) {
        throw new Error(`${field} exceeds its limit of ${limit} UTF-8 bytes.`);
      }
    } else if (
      Array.isArray(value) &&
      value.every((item) => typeof item === "string")
    ) {
      if (value.some((item) => Buffer.byteLength(item) > 512)) {
        throw new Error(`${field} entries exceed the limit of 512 UTF-8 bytes.`);
      }
    } else {
      validateModelStrings(value);
    }
  }
}

function materializeDetailDefaults(rootSchema, value, fieldSchema) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return;
  }
  const reference =
    fieldSchema.$ref ?? fieldSchema.anyOf?.find((branch) => branch.$ref)?.$ref;
  if (!reference) {
    return;
  }
  const name = reference.split("/").at(-1);
  const definition = rootSchema.$defs[name];
  const err = validateNode(rootSchema, { $ref: reference }, value, "", true);
  if (err !== null) {
    throw new Error(`${name}: ${err}`);
  }
  for (const [field, childSchema] of Object.entries(definition.properties ?? {})) {
    materializeDetailDefaults(rootSchema, value[field], childSchema);
  }
}

function normalizeEvidenceDetails(rootSchema, value) {
  if (value !== null && typeof value === "object") {
    const fields = value;
    if (Array.isArray(fields["packages"])) {
      for (const pkg of fields["packages"]) {
        if (pkg && typeof pkg === "object" && pkg["vulnerable_version_range"] === null) {
          delete pkg["vulnerable_version_range"];
        }
      }
    }
    if (fields["details"] === null) {
      delete fields["details"];
    } else {
      const details = fields["details"];
      if (details && typeof details === "object" && !Array.isArray(details)) {
        for (const field of ["repository", "advisory"]) {
          if (details[field] === null) {
            delete details[field];
          }
        }
      }
      materializeDetailDefaults(
        rootSchema,
        fields["details"],
        rootSchema.$defs["ImportedFindingEvidence"].properties["details"]
      );
    }
  }
}

function validator(name) {
  return (input) => {
    const rootSchema = loadRootSchema();
    if (name === "ImportedFindingEvidence") {
      normalizeEvidenceDetails(rootSchema, input);
    } else if (input && typeof input === "object") {
      if (name === "SourceReport" && "evidence" in input) {
        normalizeEvidenceDetails(rootSchema, input.evidence);
      }
      if (
        name === "FindingImportRequest" &&
        "items" in input &&
        Array.isArray(input.items)
      ) {
        for (const item of input.items) {
          normalizeEvidenceDetails(rootSchema, item?.evidence);
        }
      }
    }
    const err = validateNode(rootSchema, { $ref: `#/$defs/${name}` }, input, "", true);
    if (err !== null) {
      throw new Error(`${name}: ${err}`);
    }
    validateModelStrings(input);
    return input;
  };
}

const evidence = validator("ImportedFindingEvidence");
const request = validator("FindingImportRequest");
export const validateImportReceipt = validator("FindingImportReceipt");
export const validateRepositories = validator("ImportRepositoryPage");
export const validateSourceReports = validator("SourceReportPage");
export const validateSourceReport = validator("SourceReport");

export function validateExternalEvidence(input) {
  const result = evidence(input);
  for (const location of result.locations ?? []) {
    const path = location.path.replaceAll("\\", "/");
    if (
      path.startsWith("/") ||
      /^[A-Za-z]:/.test(path) ||
      path.split("/").includes("..")
    ) {
      throw new Error("Locations must use repository-relative paths.");
    }
  }
  const details = result.details;
  if (details) {
    if (details.kind === "advisory") {
      if (!details.advisory) {
        throw new Error("Advisory evidence requires its source context.");
      }
      if (details.advisory.source === "global" && details.repository) {
        throw new Error("Global advisory evidence cannot claim a source repository.");
      }
      if (details.advisory.source === "repository" && !details.repository) {
        throw new Error("Repository advisory evidence requires its source repository.");
      }
    } else {
      if (!details.repository) {
        throw new Error("Repository finding evidence requires its source repository.");
      }
      if (details.advisory) {
        throw new Error("Advisory source context requires advisory evidence.");
      }
    }
  }
  const endLine = result.details?.code?.end_line;
  if (endLine !== null && endLine !== undefined) {
    const firstLine = result.locations?.[0]?.line;
    if (firstLine === null || firstLine === undefined || endLine < firstLine) {
      throw new Error(
        "The code end line requires a first source location line and cannot precede it."
      );
    }
  }
  const urls = [
    result.url,
    result.details?.repository?.url,
    result.details?.file_url
  ];
  for (const value of urls) {
    if (value === null || value === undefined) {
      continue;
    }
    const url = value
      .replace(/[\t\r\n]/gu, "")
      .replace(/^[\u0000-\u0020]+/u, "");
    const authority = /^https?:\/\/([^/?#]+)/iu.exec(url)?.[1];
    const normalizedAuthority = (authority ?? "")
      .replace(/[@:#?]/gu, "")
      .normalize("NFKC");
    let validHost = true;
    if (authority?.includes("[") || authority?.includes("]")) {
      const hostname = /^\[([^\]]+)\](?::[\s\S]*)?$/u.exec(authority)?.[1];
      const [address, scope, extraScope] = (hostname ?? "").split("%");
      validHost =
        hostname !== undefined &&
        (/^v[a-fA-F0-9]+\.[\s\S]+$/u.test(hostname) ||
          (isIP(address) === 6 && scope !== "" && extraScope === undefined));
    }
    if (
      !authority ||
      authority.includes("@") ||
      /[/?#@:]/u.test(normalizedAuthority) ||
      !validHost
    ) {
      throw new Error("Evidence URLs must be HTTP(S) links without credentials.");
    }
  }
  let numericByteAdjustment = 0;
  const pending = [[result, 0]];
  while (pending.length > 0) {
    const [value, depth] = pending.pop();
    if (depth > 20) {
      throw new Error("Evidence exceeds the JSON depth limit of 20.");
    }
    if (value !== null && typeof value === "object") {
      for (const child of Object.values(value)) {
        pending.push([child, depth + 1]);
      }
    } else if (typeof value === "number") {
      if (!Number.isFinite(value)) {
        throw new Error("Evidence must contain finite JSON numbers.");
      }
      if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
        throw new Error(
          "Evidence integers must be within JavaScript's safe integer range; export larger values as strings to preserve them exactly."
        );
      }
      const wire = JSON.stringify(value);
      const cloud = (
        wire.includes(".") && Math.abs(value) < 1e-4
          ? value.toExponential()
          : wire
      ).replace(/e-(\d)$/u, "e-0$1");
      numericByteAdjustment += cloud.length - wire.length;
    }
  }
  if (
    Buffer.byteLength(JSON.stringify(result)) + numericByteAdjustment >
    256 * 1024
  ) {
    throw new Error("Evidence exceeds the limit of 256 KiB.");
  }
  return result;
}

export function validateImportRequest(input) {
  const result = request(input);
  if (
    new Set(result.items.map((item) => item.client_id)).size !==
    result.items.length
  ) {
    throw new Error("Import contains duplicate client IDs.");
  }
  if (
    new Set(result.items.map((item) => item.source_finding_id)).size !==
    result.items.length
  ) {
    throw new Error("Import contains duplicate source finding identities.");
  }
  for (const item of result.items) {
    validateExternalEvidence(item.evidence);
  }
  if (Buffer.byteLength(JSON.stringify(result)) > 5 * 1024 * 1024) {
    throw new Error("Import exceeds the limit of 5 MiB.");
  }
  return result;
}

export const validateExternalFindingRequest = validateImportRequest;
export const validateFindingImportReceipt = validateImportReceipt;
export const validateSourceReportPage = validateSourceReports;
