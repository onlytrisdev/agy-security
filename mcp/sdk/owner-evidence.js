import { execFile as execFileCallback } from "node:child_process";
import { readFile, realpath } from "node:fs/promises";
import { dirname, isAbsolute, join, posix, relative, resolve, sep } from "node:path";
import { promisify } from "node:util";
import { matchCodeowners, parseCodeowners } from "./codeowners.js";
import { resolveTrustedExecutable } from "./trusted-executable.js";

const execFile = promisify(execFileCallback);

const CODEOWNERS_LOCATIONS = [
  "CODEOWNERS",
  ".github/CODEOWNERS",
  "docs/CODEOWNERS",
  ".gitlab/CODEOWNERS"
];

const MAX_RECENT_COMMITS_PER_PATH = 8;

const GIT_REPOSITORY_OVERRIDE_VARS = new Set([
  "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  "GIT_CEILING_DIRECTORIES",
  "GIT_COMMON_DIR",
  "GIT_DIR",
  "GIT_DISCOVERY_ACROSS_FILESYSTEM",
  "GIT_GRAFT_FILE",
  "GIT_IMPLICIT_WORK_TREE",
  "GIT_INDEX_FILE",
  "GIT_NAMESPACE",
  "GIT_NO_REPLACE_OBJECTS",
  "GIT_OBJECT_DIRECTORY",
  "GIT_PREFIX",
  "GIT_REPLACE_REF_BASE",
  "GIT_SHALLOW_FILE",
  "GIT_WORK_TREE"
]);

export async function collectOwnerEvidence(repository, targets, signal) {
  const canonicalRepo = await realpath(repository).catch(() => resolve(repository));
  const codeowners = await loadCodeowners(canonicalRepo, signal);
  const paths = new Map();

  for (const target of targets) {
    for (const loc of target.locations) {
      const normalized = normalizeRepoRelativePath(canonicalRepo, loc.path);
      if (normalized === null) {
        continue;
      }
      let entry = paths.get(normalized);
      if (entry === undefined) {
        entry = { lineRanges: [] };
        paths.set(normalized, entry);
      }
      const start = Math.max(1, loc.startLine ?? 1);
      const end = Math.max(start, loc.endLine ?? start);
      if (
        !entry.lineRanges.some(
          ([existingStart, existingEnd]) =>
            existingStart === start && existingEnd === end
        )
      ) {
        entry.lineRanges.push([start, end]);
      }
    }
  }

  const evidenceByPath = new Map();
  for (const [repoPath, { lineRanges }] of paths) {
    throwIfAborted(signal);
    const matched =
      codeowners !== null ? matchCodeowners(codeowners.rules, repoPath) : null;
    const [blameAuthors, recentCommits] = await Promise.all([
      collectBlameAuthors(canonicalRepo, repoPath, lineRanges, signal),
      collectRecentCommits(canonicalRepo, repoPath, signal)
    ]);
    evidenceByPath.set(repoPath, {
      path: repoPath,
      codeowners:
        matched !== null && codeowners !== null
          ? {
              sourceFile: codeowners.sourceFile,
              lineNumber: matched.lineNumber,
              pattern: matched.pattern,
              owners: matched.owners
            }
          : null,
      blameAuthors,
      recentCommits
    });
  }

  return {
    codeownersFile: codeowners?.sourceFile ?? null,
    byPath: [...evidenceByPath.values()]
  };
}

export async function suggestFindingOwners(repository, findings, signal) {
  const normalizedFindings = findings.map((f, index) => ({
    findingId: String(f.findingId ?? f.id ?? `finding-${index + 1}`),
    title: typeof f.title === "string" ? f.title : `Finding ${index + 1}`,
    locations: Array.isArray(f.locations)
      ? f.locations
          .filter((l) => l && typeof l.path === "string")
          .map((l) => ({
            path: l.path,
            startLine:
              typeof l.startLine === "number"
                ? l.startLine
                : typeof l.line === "number"
                  ? l.line
                  : undefined,
            endLine:
              typeof l.endLine === "number"
                ? l.endLine
                : typeof l.startLine === "number"
                  ? l.startLine
                  : typeof l.line === "number"
                    ? l.line
                    : undefined
          }))
      : []
  }));

  const evidence = await collectOwnerEvidence(repository, normalizedFindings, signal);
  const byPathMap = new Map(evidence.byPath.map((entry) => [entry.path, entry]));
  const canonicalRepo = await realpath(repository).catch(() => resolve(repository));

  const suggestions = normalizedFindings.map((finding) => {
    const candidateMap = new Map();
    const matchedPaths = [];

    for (const loc of finding.locations) {
      const repoPath = normalizeRepoRelativePath(canonicalRepo, loc.path);
      if (!repoPath) continue;
      const pathEvidence = byPathMap.get(repoPath);
      if (!pathEvidence) continue;
      matchedPaths.push(repoPath);

      if (pathEvidence.codeowners) {
        for (const owner of pathEvidence.codeowners.owners) {
          const key = `codeowners:${owner.toLowerCase()}`;
          const existing = candidateMap.get(key) ?? {
            owner,
            kind: owner.includes("@") && !owner.startsWith("@") ? "email" : owner.includes("/") ? "team" : "handle",
            score: 0,
            confidence: "high",
            sources: new Set(),
            rationaleParts: []
          };
          existing.score += 100;
          existing.sources.add("codeowners");
          existing.rationaleParts.push(
            `${pathEvidence.codeowners.sourceFile}:${pathEvidence.codeowners.lineNumber} (${pathEvidence.codeowners.pattern}) -> ${owner}`
          );
          candidateMap.set(key, existing);
        }
      }

      for (const blame of pathEvidence.blameAuthors) {
        const key = `git:${blame.email.toLowerCase()}`;
        const existing = candidateMap.get(key) ?? {
          owner: `${blame.author} <${blame.email}>`,
          author: blame.author,
          email: blame.email,
          kind: "person",
          score: 0,
          confidence: "high",
          sources: new Set(),
          rationaleParts: []
        };
        existing.score += Math.min(60, blame.lines * 10);
        existing.sources.add("git_blame");
        existing.rationaleParts.push(
          `git blame on ${repoPath} (${blame.lines} line${blame.lines === 1 ? "" : "s"}, last touched ${blame.lastCommitDate})`
        );
        candidateMap.set(key, existing);
      }

      for (const commit of pathEvidence.recentCommits) {
        const key = `git:${commit.email.toLowerCase()}`;
        const existing = candidateMap.get(key) ?? {
          owner: `${commit.author} <${commit.email}>`,
          author: commit.author,
          email: commit.email,
          kind: "person",
          score: 0,
          confidence: "medium",
          sources: new Set(),
          rationaleParts: []
        };
        existing.score += 15;
        existing.sources.add("git_log");
        existing.rationaleParts.push(
          `recent commit ${commit.commit.slice(0, 8)} on ${repoPath} (${commit.date}: ${commit.subject})`
        );
        candidateMap.set(key, existing);
      }
    }

    const candidates = [...candidateMap.values()]
      .sort((a, b) => b.score - a.score)
      .slice(0, 5)
      .map((c) => ({
        owner: c.owner,
        kind: c.kind,
        confidence: c.score >= 80 ? "high" : c.score >= 30 ? "medium" : "low",
        sources: [...c.sources],
        rationale: [...new Set(c.rationaleParts)].slice(0, 3).join("; ")
      }));

    return {
      findingId: finding.findingId,
      title: finding.title,
      paths: [...new Set(matchedPaths)],
      recommendedOwner: candidates[0]?.owner ?? null,
      candidates
    };
  });

  return {
    repository: canonicalRepo,
    codeownersFile: evidence.codeownersFile,
    evidence: evidence.byPath,
    suggestions
  };
}

async function loadCodeowners(repository, signal) {
  for (const relPath of CODEOWNERS_LOCATIONS) {
    throwIfAborted(signal);
    const candidate = join(repository, ...relPath.split("/"));
    try {
      const real = await realpath(candidate);
      if (!isRealpathInsideRepo(repository, real)) {
        continue;
      }
      const contents = await readFile(real, { encoding: "utf8", signal });
      return {
        sourceFile: relPath,
        rules: parseCodeowners(contents)
      };
    } catch {
      // Try next location.
    }
  }
  return null;
}

export function normalizeRepoRelativePath(repository, rawPath) {
  const trimmed = rawPath.trim();
  if (!trimmed) {
    return null;
  }
  const normalizedSep = trimmed.split("\\").join("/");
  const resolved = isAbsolute(trimmed)
    ? resolve(trimmed)
    : resolve(repository, ...normalizedSep.split("/"));
  const rel = relative(repository, resolved);
  if (!rel || rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
    return null;
  }
  const posixPath = rel.split(sep).join(posix.sep);
  if (posixPath === ".git" || posixPath.startsWith(".git/")) {
    return null;
  }
  return posixPath;
}

function isRealpathInsideRepo(repository, candidateRealpath) {
  const rel = relative(repository, candidateRealpath);
  return (
    Boolean(rel) &&
    rel !== ".." &&
    !rel.startsWith(`..${sep}`) &&
    !isAbsolute(rel)
  );
}

async function collectBlameAuthors(repository, repoPath, lineRanges, signal) {
  const ranges = lineRanges.length > 0 ? lineRanges.slice(0, 4) : [[1, 50]];
  const byEmail = new Map();

  for (const [start, end] of ranges) {
    const clampedEnd = Math.min(end, start + 60);
    const out = await runGit(
      repository,
      [
        "blame",
        "--line-porcelain",
        `-L${start},${clampedEnd}`,
        "HEAD",
        "--",
        repoPath
      ],
      signal
    );
    if (out === null) {
      continue;
    }
    parseBlamePorcelain(out, byEmail);
  }

  return [...byEmail.values()]
    .sort(
      (a, b) =>
        b.lines - a.lines || b.lastCommitDate.localeCompare(a.lastCommitDate)
    )
    .slice(0, 6);
}

export function parseBlamePorcelain(output, into = new Map()) {
  let currentAuthor = "";
  let currentEmail = "";
  let currentTime = 0;

  for (const line of output.split(/\r?\n/u)) {
    if (line.startsWith("author ")) {
      currentAuthor = line.slice("author ".length).trim();
    } else if (line.startsWith("author-mail ")) {
      currentEmail = line
        .slice("author-mail ".length)
        .trim()
        .replace(/^<|>$/gu, "");
    } else if (line.startsWith("author-time ")) {
      const parsed = Number.parseInt(line.slice("author-time ".length).trim(), 10);
      currentTime = Number.isFinite(parsed) ? parsed : 0;
    } else if (line.startsWith("\t")) {
      if (!currentAuthor && !currentEmail) {
        continue;
      }
      if (
        currentAuthor === "Not Committed Yet" ||
        currentEmail === "not.committed.yet"
      ) {
        continue;
      }
      const key = `${currentAuthor.toLowerCase()}|${currentEmail.toLowerCase()}`;
      const isoDate =
        currentTime > 0
          ? new Date(currentTime * 1000).toISOString().slice(0, 10)
          : "";
      const existing = into.get(key);
      if (existing === undefined) {
        into.set(key, {
          author: currentAuthor,
          email: currentEmail,
          lines: 1,
          lastCommitDate: isoDate
        });
      } else {
        existing.lines += 1;
        if (isoDate > existing.lastCommitDate) {
          existing.lastCommitDate = isoDate;
        }
      }
    }
  }
  return into;
}

async function collectRecentCommits(repository, repoPath, signal) {
  const out = await runGit(
    repository,
    [
      "log",
      "--follow",
      `-n${MAX_RECENT_COMMITS_PER_PATH}`,
      "--date=short",
      "--format=%H%x1f%an%x1f%ae%x1f%ad%x1f%s",
      "HEAD",
      "--",
      repoPath
    ],
    signal
  );
  if (out === null) {
    return [];
  }
  return parseGitLogCommits(out);
}

export function parseGitLogCommits(output) {
  const commits = [];
  for (const rawLine of output.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (!line) {
      continue;
    }
    const [commit, author, email, date, subject] = line.split("\x1f");
    if (!commit || !author) {
      continue;
    }
    commits.push({
      commit,
      author,
      email: email ?? "",
      date: date ?? "",
      subject: subject ?? ""
    });
  }
  return commits;
}

async function runGit(repository, args, signal) {
  throwIfAborted(signal);
  try {
    const cleanEnv = sanitizeGitEnvironment(process.env);
    const trusted = await resolveTrustedExecutable(
      "git",
      cleanEnv,
      protectedCheckouts(repository)
    );
    if (trusted === null) {
      return null;
    }
    const { stdout } = await execFile(
      trusted.executable,
      ["-c", "core.fsmonitor=false", "-C", repository, ...args],
      {
        encoding: "utf8",
        signal,
        env: trusted.environment,
        maxBuffer: 4 * 1024 * 1024
      }
    );
    return stdout;
  } catch (error) {
    throwIfAborted(signal);
    if (error instanceof Error && error.name === "AbortError") {
      throw error;
    }
    return null;
  }
}

function protectedCheckouts(repository) {
  return [resolve(repository)];
}

export function sanitizeGitEnvironment(source) {
  const sanitized = { ...source };
  for (const name of Object.keys(sanitized)) {
    const upper = name.toUpperCase();
    if (
      GIT_REPOSITORY_OVERRIDE_VARS.has(upper) ||
      upper === "GIT_ALLOW_PROTOCOL" ||
      upper.startsWith("GIT_CONFIG_")
    ) {
      delete sanitized[name];
    }
  }
  sanitized["GIT_ALLOW_PROTOCOL"] = "";
  sanitized["GIT_TERMINAL_PROMPT"] = "0";
  return sanitized;
}

function throwIfAborted(signal) {
  if (signal?.aborted === true) {
    throw (
      signal.reason ??
      new DOMException("The operation was aborted.", "AbortError")
    );
  }
}
