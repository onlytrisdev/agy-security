import { constants } from "node:fs";
import { access, realpath, stat } from "node:fs/promises";
import {
  basename,
  delimiter,
  dirname,
  extname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep
} from "node:path";

export async function resolveTrustedExecutable(
  candidate,
  environment,
  protectedRoot
) {
  const inspected = await inspectTrustedExecutable(
    candidate,
    environment,
    protectedRoot
  );
  return inspected.executable === null
    ? null
    : { executable: inspected.executable, environment: inspected.environment };
}

export async function inspectTrustedExecutable(
  candidate,
  environment,
  protectedRoot
) {
  const roots = await Promise.all(
    (typeof protectedRoot === "string" ? [protectedRoot] : protectedRoot).map(
      (root) => realpath(root).catch(() => resolve(root))
    )
  );
  const isProtected = (path) => roots.some((root) => isWithin(root, path));
  const path =
    environment["PATH"] ??
    Object.entries(environment).find(
      ([name]) => name.toUpperCase() === "PATH"
    )?.[1];
  const entries = [];
  for (let entry of path?.split(delimiter) ?? []) {
    if (
      process.platform === "win32" &&
      entry.startsWith('"') &&
      entry.endsWith('"')
    ) {
      entry = entry.slice(1, -1);
    }
    if (entry.length === 0) {
      continue;
    }
    const canonical = await realpath(entry).catch(() => null);
    if (canonical === null || isProtected(canonical)) {
      continue;
    }
    if (!entries.includes(canonical)) {
      entries.push(canonical);
    }
  }
  const pathLike = candidate.includes("/") || candidate.includes("\\");
  const extensions =
    process.platform === "win32"
      ? /\.(?:exe|com)$/iu.test(candidate)
        ? [{ suffix: "", runnable: true }]
        : pathLike
          ? extname(candidate) === ""
            ? [{ suffix: ".exe", runnable: true }]
            : [{ suffix: "", runnable: false }]
          : [
              { suffix: ".exe", runnable: true },
              { suffix: ".com", runnable: true },
              { suffix: ".bat", runnable: false },
              { suffix: ".cmd", runnable: false },
              { suffix: "", runnable: false }
            ]
      : [{ suffix: "", runnable: true }];
  const candidates = pathLike
    ? extensions.map((extension) => ({
        entry: null,
        path:
          process.platform === "win32"
            ? resolve(`${candidate}${extension.suffix}`)
            : candidate,
        runnable: extension.runnable
      }))
    : entries.flatMap((entry) =>
        extensions.map((extension) => ({
          entry,
          path: join(entry, `${candidate}${extension.suffix}`),
          runnable: extension.runnable
        }))
      );
  const unsafeEntries = new Set();
  let executable = null;
  for (const current of candidates) {
    const canonical = await realpath(current.path).catch(() => null);
    if (canonical === null) {
      continue;
    }
    if (isProtected(canonical)) {
      if (current.entry !== null) {
        unsafeEntries.add(current.entry);
      }
      continue;
    }
    if (process.platform === "win32" && /\.(?:bat|cmd)$/iu.test(canonical)) {
      continue;
    }
    if (!current.runnable) {
      continue;
    }
    try {
      await access(
        canonical,
        process.platform === "win32" ? constants.F_OK : constants.X_OK
      );
      if (!(await stat(canonical)).isFile()) {
        continue;
      }
      const invocationPath = pathLike
        ? join(await realpath(dirname(current.path)), basename(current.path))
        : current.path;
      executable ??=
        pathLike && (isProtected(current.path) || isProtected(invocationPath))
          ? canonical
          : invocationPath;
    } catch {
      continue;
    }
  }
  const sanitizedEnvironment = { ...environment };
  for (const name of Object.keys(sanitizedEnvironment)) {
    if (name.toUpperCase() === "PATH") {
      delete sanitizedEnvironment[name];
    }
  }
  sanitizedEnvironment["PATH"] = entries
    .filter((entry) => !unsafeEntries.has(entry))
    .join(delimiter);
  return { executable, environment: sanitizedEnvironment };
}

export function isWithin(root, candidate) {
  const path = relative(root, candidate);
  return (
    path === "" ||
    (path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path))
  );
}
