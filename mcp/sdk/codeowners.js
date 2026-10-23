export function parseCodeowners(source) {
  const rules = [];
  for (const [index, line] of source.split(/\r?\n/u).entries()) {
    const value = line.trimStart();
    if (!value || value.startsWith("#")) {
      continue;
    }
    const token = /^(?:\\.|[^\s])+/u.exec(value)[0];
    const matches = codeownersPattern(token);
    if (matches === null) {
      continue;
    }
    const handles = value
      .slice(token.length)
      .split("#", 1)[0]
      .trim()
      .split(/\s+/u)
      .filter(Boolean);
    const owners = [];
    let valid = true;
    for (const handle of handles) {
      if (/^@[a-z\d](?:[a-z\d_-]*[a-z\d])?(?:\/[a-z\d_.-]+)?$/i.test(handle)) {
        owners.push(
          handle.includes("/")
            ? { kind: "group", provider: "github", handle: handle.slice(1) }
            : { kind: "person", provider: "github", handle: handle.slice(1) }
        );
      } else if (/^[^@\s]+@[^@\s]+$/u.test(handle)) {
        owners.push({ kind: "person", email: handle });
      } else {
        valid = false;
        break;
      }
    }
    if (valid) {
      rules.push({
        pattern: token,
        line: index + 1,
        rule: line,
        owners,
        matches
      });
    }
  }
  return rules;
}

function codeownersPattern(pattern) {
  if (pattern.startsWith("!") || pattern.startsWith("\\#")) {
    return null;
  }
  const anchored = pattern.startsWith("/");
  if (anchored) {
    pattern = pattern.slice(1);
  }
  const directory = pattern.endsWith("/");
  if (directory) {
    pattern = pattern.slice(0, -1);
  }
  const rooted = anchored || pattern.includes("/");
  const immediate = /(?:^|\/)[*?]$/u.test(pattern);
  const characters = Array.from(pattern);
  const tokens = [];
  for (let index = 0; index < characters.length; index++) {
    const character = characters[index];
    if (character === "\\" && index + 1 < characters.length) {
      tokens.push({ literal: characters[++index] });
    } else if (
      character === "[" ||
      character === "]" ||
      (character === "*" &&
        characters[index + 1] === "*" &&
        characters[index + 2] === "*")
    ) {
      return null;
    } else if (
      character === "*" &&
      characters[index + 1] === "*" &&
      (index === 0 || characters[index - 1] === "/") &&
      (index + 2 === characters.length || characters[index + 2] === "/")
    ) {
      if (characters[index + 2] === "/") {
        tokens.push("**/");
        index += 2;
      } else {
        tokens.push("**");
        index++;
      }
    } else if (character === "*" || character === "?") {
      tokens.push(character);
    } else {
      tokens.push({ literal: character });
    }
  }
  return (path) => {
    let active = new Set([0]);
    let next = new Set();
    for (let offset = 0; ; ) {
      const boundary = offset === 0 || path[offset - 1] === "/";
      if (!rooted && boundary) {
        active.add(0);
      }
      for (const index of active) {
        const token = tokens[index];
        if (token === "*" || token === "**" || (token === "**/" && boundary)) {
          active.add(index + 1);
        }
      }
      const end = offset === path.length;
      if (
        active.has(tokens.length) &&
        (directory ? path[offset] === "/" : end || (!immediate && path[offset] === "/"))
      ) {
        return true;
      }
      if (end) {
        return false;
      }
      const character = String.fromCodePoint(path.codePointAt(offset));
      next.clear();
      for (const index of active) {
        const token = tokens[index];
        if (token === undefined) {
          continue;
        }
        if (typeof token === "object") {
          if (token.literal === character) {
            next.add(index + 1);
          }
        } else if (token === "?") {
          if (character !== "/") {
            next.add(index + 1);
          }
        } else if (token !== "*" || character !== "/") {
          next.add(index);
        }
      }
      if (rooted && next.size === 0) {
        return false;
      }
      [active, next] = [next, active];
      offset += character.length;
    }
  };
}

export function codeownersForPath(rules, path) {
  return rules.findLast(({ matches }) => matches(path));
}

export function matchCodeowners(rules, path) {
  const rule = codeownersForPath(rules, path);
  if (!rule || rule.owners.length === 0) {
    return null;
  }
  return {
    lineNumber: rule.line,
    pattern: rule.pattern,
    rule: rule.rule,
    owners: rule.owners.map((o) =>
      "email" in o ? o.email : `@${o.handle}`
    )
  };
}
