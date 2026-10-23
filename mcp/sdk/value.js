export function isSafeNonNegativeInteger(value) {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

export function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

export function parseJson(read) {
  try {
    return JSON.parse(read());
  } catch {
    return null;
  }
}

export const findingEntry = (finding) => [finding.findingId, finding];

export function notify(callback) {
  try {
    void Promise.resolve(callback()).catch(() => {});
  } catch {}
}
