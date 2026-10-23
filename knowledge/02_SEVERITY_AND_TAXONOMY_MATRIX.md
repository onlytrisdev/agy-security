# AGY-Security Pre-Compiled Severity & Taxonomy Reference

## 1. Severity Calibration Matrix

| Impact \ Likelihood | High Likelihood | Medium / Unknown Likelihood | Low Likelihood |
| :--- | :--- | :--- | :--- |
| **Severe / Immediate Compromise** | `critical` (`[P0]`) | `high` (`[P1]`) | `medium` (`[P2]`) |
| **High Impact** | `high` (`[P1]`) | `medium` (`[P2]`) | `low` (`[P3]`) |
| **Medium / Unknown Impact** | `medium` (`[P2]`) | `low` (`[P3]`) | `low` (`[P3]`) |
| **Low Impact** | `low` (`[P3]`) | `low` (`[P3]`) | `low` (`[P3]`) |

- **Downgrade Rules**: Downgrade by 1 level for internal-only, same-tenant, localhost-only, or heavily constrained administrative paths.
- **Exclusion Rules**: Do NOT report self-XSS, privileged operator behavior that grants no new boundary crossing, dummy placeholder keys, or theoretical issues without `path:line` source evidence.

## 2. Canonical `ruleId` & `taxonomy.cwe` Quick Lookup

| Vulnerability Class | Canonical `ruleId` Prefix | `taxonomy.category` | `taxonomy.cwe` |
| :--- | :--- | :--- | :--- |
| SQL Injection | `sql-injection.<sink>` | `Improper SQL Query Parameterization` | `["CWE-89"]` |
| Command Injection | `command-injection.<sink>` | `Improper OS Command Neutralization` | `["CWE-78"]` |
| Code Injection / Eval | `code-injection.<sink>` | `Dynamic Code Execution` | `["CWE-94"]` |
| Path Traversal / ZipSlip | `path-traversal.<sink>` | `Missing Path Containment Check` | `["CWE-22"]` |
| Server-Side Request Forgery | `ssrf.<sink>` | `Unrestricted Outbound Request Destination` | `["CWE-918"]` |
| Cross-Site Scripting (XSS) | `xss.<sink>` | `Unescaped Output Encoding` | `["CWE-79"]` |
| Missing Auth / Broken Access | `broken-access-control.<route>` | `Missing Authorization / Ownership Guard` | `["CWE-862", "CWE-639"]` |
| Authentication Bypass / JWT | `auth-bypass.<mechanism>` | `Broken Authentication Verification` | `["CWE-287"]` |
| Insecure Deserialization | `insecure-deserialization.<parser>` | `Untrusted Object Deserialization` | `["CWE-502"]` |
| Hardcoded Secret / Key | `hardcoded-secret.<type>` | `Embedded Credential in Source` | `["CWE-798"]` |
| Weak Cryptography / Hash | `weak-crypto.<primitive>` | `Broken or Risky Cryptographic Algorithm` | `["CWE-327"]` |
| Race Condition / TOCTOU | `race-condition.<operation>` | `Time-of-Check Time-of-Use State Race` | `["CWE-362"]` |
