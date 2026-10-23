import { validateExternalEvidence } from "./external-import-contract.js";

const profile = "wiz-code-vulnerability-csv";
const requiredHeaders = [
  "ID",
  "Name",
  "DetailedName",
  "AssetID",
  "WizURL",
  "CloudPlatform",
  "CloudProviderURL"
];

function text(value) {
  return typeof value === "string" && value.trim() ? value : null;
}

function parseCsvRows(source) {
  const data = [];
  const errors = [];
  let row = [];
  let field = "";
  let inQuotes = false;
  let fieldStartedWithQuote = false;
  let afterClosingQuote = false;
  let rowNumber = 0;

  for (let i = 0; i < source.length; i++) {
    const ch = source[i];
    if (inQuotes) {
      if (ch === '"') {
        if (source[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
          afterClosingQuote = true;
        }
      } else {
        field += ch;
      }
      continue;
    }

    if (afterClosingQuote) {
      if (ch === ",") {
        row.push(field);
        field = "";
        fieldStartedWithQuote = false;
        afterClosingQuote = false;
        continue;
      }
      if (ch === "\r" || ch === "\n") {
        if (ch === "\r" && source[i + 1] === "\n") {
          i++;
        }
        row.push(field);
        if (!(row.length === 1 && row[0] === "" && !fieldStartedWithQuote)) {
          data.push(row);
        }
        row = [];
        field = "";
        fieldStartedWithQuote = false;
        afterClosingQuote = false;
        rowNumber++;
        continue;
      }
      errors.push({
        type: "Quotes",
        code: "InvalidQuotes",
        message: "Trailing quote characters are malformed.",
        row: rowNumber
      });
      afterClosingQuote = false;
      field += ch;
      continue;
    }

    if (ch === '"') {
      if (field.length === 0) {
        inQuotes = true;
        fieldStartedWithQuote = true;
      } else {
        errors.push({
          type: "Quotes",
          code: "InvalidQuotes",
          message: "Unexpected quote in unquoted field.",
          row: rowNumber
        });
        field += ch;
      }
      continue;
    }

    if (ch === ",") {
      row.push(field);
      field = "";
      fieldStartedWithQuote = false;
      continue;
    }

    if (ch === "\r" || ch === "\n") {
      if (ch === "\r" && source[i + 1] === "\n") {
        i++;
      }
      row.push(field);
      if (!(row.length === 1 && row[0] === "" && !fieldStartedWithQuote)) {
        data.push(row);
      }
      row = [];
      field = "";
      fieldStartedWithQuote = false;
      rowNumber++;
      continue;
    }

    field += ch;
  }

  if (inQuotes) {
    errors.push({
      type: "Quotes",
      code: "MissingQuotes",
      message: "Quoted field unterminated.",
      row: rowNumber
    });
  }
  if (row.length > 0 || field.length > 0 || fieldStartedWithQuote) {
    row.push(field);
    if (!(row.length === 1 && row[0] === "" && !fieldStartedWithQuote)) {
      data.push(row);
    }
  }
  return { data, errors };
}

export function readWizCsv(contents) {
  try {
    JSON.parse(contents.trimStart().split(/\r?\n/u, 1)[0]);
    return undefined;
  } catch {
    // A CSV header is not a JSON value.
  }
  const parsed = parseCsvRows(contents);
  const [headers, ...rows] = parsed.data;
  if (!headers || !requiredHeaders.every((name) => headers.includes(name))) {
    return undefined;
  }
  if (parsed.errors.length) {
    throw new Error(`Invalid Wiz CSV: ${parsed.errors[0].message}`);
  }
  if (new Set(headers).size !== headers.length) {
    throw new Error("Wiz CSV contains duplicate column names.");
  }
  return rows.map((cells, index) => {
    if (cells.length !== headers.length) {
      throw new Error(`Wiz CSV row ${index + 2} has the wrong column count.`);
    }
    return Object.fromEntries(headers.map((name, i) => [name, cells[i]]));
  });
}

function repositoryUrl(row) {
  if (text(row["CloudPlatform"])?.trim().toLowerCase() !== "github") {
    throw new Error(
      "Wiz CSV imports require GitHub repository-branch findings. Workload and other provider CSV reports need an explicit normalized JSONL mapping."
    );
  }
  const value = text(row["CloudProviderURL"]);
  const url = value ? new URL(value) : undefined;
  const origin = value?.match(/^(https?:\/\/[^/?#]+)/iu)?.[1];
  const path = url?.pathname.match(/^\/([^/]+)\/([^/]+)\/tree\/(.+)$/u);
  if (
    !url ||
    !origin ||
    !["http:", "https:"].includes(url.protocol) ||
    url.username ||
    url.password ||
    !path
  ) {
    throw new Error(
      "Wiz CSV finding requires a GitHub repository-branch URL."
    );
  }
  return `${origin}/${path[1]}/${path[2]}`;
}

export function wizCsvRepositoryUrl(evidence) {
  const source = evidence.source_data;
  if (source?.["format"] !== profile) {
    return undefined;
  }
  const row = source["row"];
  if (!row || typeof row !== "object" || Array.isArray(row)) {
    throw new Error("Wiz CSV source evidence is missing its original row.");
  }
  return repositoryUrl(row);
}

export function wizCsvFinding(row, sourceFindingId) {
  repositoryUrl(row);
  const name = text(row["Name"]);
  const packageName = text(row["DetailedName"]);
  if (!name || !packageName || !text(row["AssetID"])) {
    throw new Error(
      "Wiz CSV finding requires Name, DetailedName, and AssetID."
    );
  }
  const path = text(text(row["LocationPath"])?.replace(/^\/+/, ""));
  const fixedVersion = text(row["FixedVersion"]);
  const severity = (
    text(row["Severity"]) ??
    text(row["VendorSeverity"]) ??
    text(row["CVSSSeverity"])
  )
    ?.trim()
    .toLowerCase();
  return {
    source_finding_id: sourceFindingId,
    evidence: validateExternalEvidence({
      title: [packageName, text(row["Version"]), name]
        .filter(Boolean)
        .join(" "),
      description: text(row["Description"]),
      severity,
      url: text(row["WizURL"]),
      advisory_ids: [name],
      packages: [
        {
          name: packageName,
          ecosystem: null,
          installed_version: text(row["Version"]),
          manifest_path: path,
          fixed_versions: fixedVersion ? [fixedVersion] : []
        }
      ],
      locations: path ? [{ path }] : [],
      branch: null,
      code_revision: null,
      source_scan_id: null,
      source_updated_at: null,
      image_digests: [],
      source_data: { format: profile, row }
    })
  };
}
