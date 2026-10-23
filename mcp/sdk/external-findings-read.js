import { wizCsvRepositoryUrl } from "./wiz-csv.js";
import { readSnykFindings, snykRepositoryUrls } from "./snyk-findings.js";
import { readSemgrepFindings } from "./semgrep-findings.js";
import { readEndorFindings, endorRepositoryUrls } from "./endor-findings.js";
import { readGitHubFindings } from "./github-findings.js";
import { isGitHubCloudHost } from "./git-remote.js";
import { isRecord } from "./record.js";
import { readVendorFindingsForPublication } from "./wiz-findings.js";

export async function readExternalFindings(path, options) {
  if (options.provider === "snyk") {
    const findings = await readSnykFindings(path);
    return {
      findings,
      sourceRepositories: findings.findings.flatMap(({ evidence }) =>
        snykRepositoryUrls(evidence.source_data, {
          normalizeGitRemote: false
        }).map((url) => ({ url }))
      )
    };
  }
  if (options.provider === "semgrep") {
    const findings = await readSemgrepFindings(path, {
      sourceRepositoryUrl: options.sourceRepositoryUrl ?? ""
    });
    const sourceRepositories = findings.findings.flatMap(({ evidence }) => {
      const context = evidence.source_data?.["runContext"];
      const references = isRecord(context)
        ? context["versionControlProvenance"]
        : undefined;
      return Array.isArray(references)
        ? references.flatMap((reference) =>
            isRecord(reference) &&
            typeof reference["repositoryUri"] === "string" &&
            reference["repositoryUri"].trim()
              ? [{ url: reference["repositoryUri"] }]
              : []
          )
        : [];
    });
    return { findings, sourceRepositories };
  }
  if (options.provider === "endor") {
    const parsed = await readEndorFindings(path);
    return {
      findings: parsed,
      sourceRepositories: parsed.findings.flatMap((finding) =>
        endorRepositoryUrls(finding.evidence.source_data).map((url) => ({
          url
        }))
      )
    };
  }
  if (options.provider === "github") {
    return { findings: await readGitHubFindings(path) };
  }
  const publication = await readVendorFindingsForPublication(path);
  const sourceRepositories = publication.current.findings.flatMap(({ evidence }) => {
    const csvUrl = wizCsvRepositoryUrl(evidence);
    if (csvUrl) {
      return [{ url: csvUrl, platform: "github" }];
    }
    const asset = evidence.source_data?.["vulnerableAsset"];
    if (!isRecord(asset) || typeof asset["cloudProviderURL"] !== "string") {
      return [];
    }
    const url = URL.parse(asset["cloudProviderURL"]);
    if (!url) {
      return [];
    }
    const github =
      asset["nativeType"] === "github#repositoryBranch" ||
      (asset["type"] === "REPOSITORY_BRANCH" && isGitHubCloudHost(url.hostname));
    if (!github) {
      return asset["type"] === "REPOSITORY_BRANCH"
        ? [{ url: asset["cloudProviderURL"] }]
        : [];
    }
    const [, owner, repository] = url.pathname.split("/");
    return owner && repository
      ? [
          {
            url: `${url.origin}/${owner}/${repository}`,
            platform: "github"
          }
        ]
      : [];
  });
  return {
    findings: publication.current,
    publication,
    sourceRepositories: [...publication.sourceRepositories, ...sourceRepositories]
  };
}
