# AGY-Security Pre-Compiled High-Signal Sink & Secret Patterns

Use these ready-made `rg` (ripgrep) and `semgrep` patterns to locate security-sensitive sinks and credentials in 1 command without reading helper scripts.

## 1. Fast Multi-Language Sink Discovery (`rg`)

### Python (`Flask`, `FastAPI`, `Django`, `AsyncIO`)
```bash
rg -n "(subprocess\.(run|Popen|call|check_output)|os\.(system|popen)|eval\(|exec\(|pickle\.loads|yaml\.(load|unsafe_load)\(|send_file\(|render_template_string\(|execute\(.*%|execute\(.*f['\"]|requests\.(get|post|request)\(|urllib\.request\.urlopen)"
```

### JavaScript / TypeScript / Node.js (`Express`, `Next.js`, `Electron`)
```bash
rg -n "(child_process|\bexec\(|\bexecSync\(|\bspawn\(|eval\(|new Function\(|dangerouslySetInnerHTML|innerHTML\s*=|res\.(sendFile|redirect)\(|\$where|\$regex|jwt\.decode\(|nodeIntegration\s*:\s*true|contextIsolation\s*:\s*false)"
```

### PHP (`Laravel`, `cPanel`, `MVC`, `WordPress`)
```bash
rg -n "(\b(exec|shell_exec|system|passthru|popen|proc_open|eval|assert|unserialize|include|include_once|require|require_once)\s*\(|\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)|->query\(.*\$|curl_setopt\(.*CURLOPT_URL)"
```

### Go / Rust / C / C++ / Android NDK
```bash
rg -n "(exec\.Command|sql\.Query.*\+|filepath\.Join|unsafe\s*\{|strcpy\(|strcat\(|sprintf\(|gets\(|memcpy\(|system\(|popen\(|dlopen\(|addJavascriptInterface|setAllowFileAccess|setAllowUniversalAccessFromFileURLs)"
```

## 2. Hardcoded Secrets & Private Keys Sweep (`rg`)
```bash
rg -n "(BEGIN (RSA|EC|OPENSSH|DSA|PRIVATE) KEY|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|gh[pousr]_[A-Za-z0-9_]{30,}|sk-[A-Za-z0-9\-_]{20,}|xox[baprs]-[0-9A-Za-z\-]+|cfut_[A-Za-z0-9_]+|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"
```

## 3. Automated CLI Scanners (Pre-Installed in Environment)
- **Python AST Security Scan**: `python -m bandit -r <target_dir> -f json -q`
- **Python Dependency CVE Audit**: `python -m pip_audit -r <requirements.txt>`
- **Semgrep Static Analysis**: `E:\LanguageLibrary\Python\Scripts\semgrep.exe scan --config auto --json --quiet <target_dir>`
