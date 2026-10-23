export function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

export function abortReason(signal) {
  return (
    signal.reason ??
    new DOMException("The operation was aborted.", "AbortError")
  );
}

export class AgySecurityError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = new.target.name;
  }
}

export const CodexSecurityError = AgySecurityError;

export class DeduplicationReviewError extends AgySecurityError {
  metadata;
  constructor(metadata, displayReason = metadata.reason) {
    super(
      `AGY did not complete a validated deduplication review. Findings are unchanged; retry the command. Reason: ${displayReason}`
    );
    this.metadata = metadata;
  }
}

export class ConfigurationError extends AgySecurityError {}
export class AuthenticationRequiredError extends AgySecurityError {}
export class PluginBootstrapError extends AgySecurityError {}
export class LocalPluginBootstrapError extends PluginBootstrapError {}
export class PluginPythonUnavailableError extends PluginBootstrapError {}
export class SandboxUnavailableError extends AgySecurityError {}
export class InvalidTargetError extends AgySecurityError {}
export class OutputDirectoryError extends AgySecurityError {}
export class IncompleteScanError extends AgySecurityError {}
export class ContractValidationError extends AgySecurityError {}
export class ScanInterruptedError extends AgySecurityError {
  scanDir;
  constructor(message, scanDir, options) {
    super(message, options);
    this.scanDir = scanDir;
  }
}
