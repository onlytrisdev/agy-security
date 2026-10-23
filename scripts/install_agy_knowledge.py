#!/usr/bin/env python3
"""
AGY-Security One-Command Installer, Pre-Compiled Knowledge & Zero-Read Optimizer.

Run this script during installation or upgrades (`python scripts/install_agy_knowledge.py`) to:
1. Register or update the `agy_security` MCP server in `~/.gemini/config/mcp_config.json`
   with `AGY_SECURITY_KNOWLEDGE_BASE` pre-configured.
2. Install the global Zero-Slash Auto-Trigger rule in `~/.gemini/config/rules/agy_security_auto_trigger.md`.
3. Install the Pre-Compiled MCP instructions in `~/.gemini/antigravity/mcp/agy_security/instructions.md`
   and compact cached MCP tool schemas (`*.json`) so `record_agy_security_scan_draft.json` never wastes tokens.
4. Synchronize `plugins/agy-security` -> `skills/agy-security`.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

GEMINI_ROOT = Path(os.environ.get("GEMINI_ROOT", str(Path.home() / ".gemini"))).resolve()
PLUGIN_ROOT = Path(__file__).resolve().parent.parent
SKILL_MIRROR_ROOT = GEMINI_ROOT / "config" / "skills" / "agy-security"
KNOWLEDGE_DIR = PLUGIN_ROOT / "knowledge"
GLOBAL_RULES_DIR = GEMINI_ROOT / "config" / "rules"
MCP_CACHE_DIR = GEMINI_ROOT / "antigravity" / "mcp" / "agy_security"
MCP_STATE_DIR = GEMINI_ROOT / "mcp" / "agy-security" / "state"
MCP_CONFIG_PATH = GEMINI_ROOT / "config" / "mcp_config.json"


AUTO_TRIGGER_RULE_CONTENT = """# AGY-Security Zero-Read Auto-Trigger & Pre-Compiled Execution Rule

1. **Zero-Slash Auto-Trigger**: Automatically run `AGY-Security` (`agy_security` MCP server + parallel subagents) on any security audit, code review, PR/diff check, threat model, PoC validation, or vulnerability fix without waiting for `/agy-...` commands.
2. **Zero-Read / Zero-Token-Waste Fast-Path**:
   - **NEVER read** `scripts/*.py`, `mcp/*.mjs`, `schemas/**/*.json`, `antigravity/mcp/agy_security/*.json`, or chain-read `references/*.md` during a scan.
   - All tool schemas, `record_agy_security_scan_draft` contracts, and subagent prompts (`agy-baseline-auditor`, `agy-threat-architect`, `agy-packet-investigator`, `agy-poc-validator`, `agy-patch-reviewer`, `agy-security-orchestrator`) are already pre-compiled in `<user_rules>` (`plugins/agy-security/rules/AGENTS.md`) and `plugins/agy-security/knowledge/`.
   - Start `start_agy_security_standard_scan` / `start_agy_security_deep_scan` / `start_agy_security_prompt_only_scan` on **Turn 1**, fan out the parallel subagent swarm with a `schedule` watchdog on **Turn 2**, submit `record_agy_security_scan_draft` on **Turn 3**, and seal with `complete_agy_security_scan` on **Turn 4**.
"""


COMPACT_SCAN_DRAFT_SCHEMA = {
    "name": "record_agy_security_scan_draft",
    "description": (
        "Save a Standard or Deep security scan checkpoint (`complete: false`) or final semantic result (`complete: true`). "
        "ZERO-READ CONTRACT: Never read scripts/*.py or schemas/*.json. "
        "Required top-level fields: scanId (UUID string), findings (array), coverage (object with surfaces, explicitExclusions, deferred). "
        "Optional top-level fields: complete (boolean), handoffClaimToken (string), scope ({ summary, artifactsReviewed, validationMode }), "
        "threatModel ({ summary, assets, trustBoundaries, attackerCapabilities, securityObjectives, assumptions })."
    ),
    "inputSchema": {
        "type": "object",
        "required": ["scanId", "findings", "coverage"],
        "additionalProperties": False,
        "properties": {
            "scanId": {"type": "string", "description": "UUID of the active scan."},
            "complete": {
                "type": "boolean",
                "description": "false for intermediate checkpoint, true for final draft before complete_agy_security_scan.",
            },
            "handoffClaimToken": {"type": "string"},
            "scope": {
                "type": "object",
                "description": "Do NOT include includePaths or excludePaths here.",
                "properties": {
                    "summary": {"type": "string"},
                    "artifactsReviewed": {"type": "array", "items": {"type": "string"}},
                    "validationMode": {"type": "string"},
                    "runtimeStatus": {"type": "string"},
                    "context": {"type": "string"},
                    "limitations": {"type": "array", "items": {"type": "string"}},
                },
            },
            "threatModel": {
                "type": "object",
                "required": ["summary"],
                "properties": {
                    "summary": {"type": "string"},
                    "assets": {"type": "array", "items": {"type": "string"}},
                    "trustBoundaries": {"type": "array", "items": {"type": "string"}},
                    "attackerCapabilities": {"type": "array", "items": {"type": "string"}},
                    "securityObjectives": {"type": "array", "items": {"type": "string"}},
                    "assumptions": {"type": "array", "items": {"type": "string"}},
                },
            },
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": [
                        "ruleId",
                        "title",
                        "summary",
                        "severity",
                        "confidence",
                        "taxonomy",
                        "locations",
                        "remediation",
                        "provenance",
                    ],
                    "properties": {
                        "ruleId": {"type": "string", "pattern": "^[a-z0-9][a-z0-9._/-]*$"},
                        "title": {"type": "string"},
                        "summary": {"type": "string"},
                        "severity": {
                            "type": "object",
                            "required": ["level"],
                            "properties": {
                                "level": {"enum": ["critical", "high", "medium", "low", "informational"]},
                                "rationale": {"type": "string"},
                                "score": {"type": "number"},
                            },
                        },
                        "confidence": {
                            "type": "object",
                            "required": ["level", "rationale"],
                            "properties": {
                                "level": {"enum": ["high", "medium", "low"]},
                                "rationale": {"type": "string"},
                            },
                        },
                        "taxonomy": {
                            "type": "object",
                            "required": ["category", "cwe"],
                            "properties": {
                                "category": {"type": "string"},
                                "cwe": {"type": "array", "items": {"type": "string"}},
                            },
                        },
                        "locations": {
                            "type": "array",
                            "minItems": 1,
                            "items": {
                                "type": "object",
                                "required": ["path", "startLine"],
                                "properties": {
                                    "path": {"type": "string"},
                                    "startLine": {"type": "integer", "minimum": 1},
                                    "endLine": {"type": "integer", "minimum": 1},
                                    "role": {"type": "string"},
                                },
                            },
                        },
                        "codeEvidence": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["id", "label", "path", "startLine", "code", "explanation"],
                                "properties": {
                                    "id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9._/-]*$"},
                                    "label": {"type": "string"},
                                    "path": {"type": "string"},
                                    "startLine": {"type": "integer", "minimum": 1},
                                    "endLine": {"type": "integer", "minimum": 1},
                                    "code": {"type": "string"},
                                    "explanation": {"type": "string"},
                                },
                            },
                        },
                        "rootCause": {
                            "type": "object",
                            "required": ["summary"],
                            "properties": {
                                "summary": {"type": "string"},
                                "evidenceRefs": {"type": "array", "items": {"type": "string"}},
                            },
                        },
                        "validation": {
                            "type": "object",
                            "properties": {
                                "status": {"type": "string"},
                                "method": {"type": "string"},
                                "summary": {"type": "string"},
                                "counterEvidence": {"type": "array", "items": {"type": "string"}},
                            },
                        },
                        "attackPath": {
                            "type": "object",
                            "properties": {
                                "summary": {"type": "string"},
                                "steps": {"type": "array", "items": {"type": "string"}},
                                "dataflow": {
                                    "type": "object",
                                    "properties": {
                                        "summary": {"type": "string"},
                                        "source": {"type": "string"},
                                        "sink": {"type": "string"},
                                    },
                                },
                                "reachability": {
                                    "type": "object",
                                    "properties": {
                                        "summary": {"type": "string"},
                                        "attacker": {"type": "string"},
                                        "entrypoint": {"type": "string"},
                                    },
                                },
                            },
                        },
                        "remediation": {"type": "string", "description": "Plain non-empty string."},
                        "provenance": {
                            "type": "object",
                            "required": ["source"],
                            "properties": {"source": {"type": "string", "default": "local_plugin"}},
                        },
                    },
                },
            },
            "coverage": {
                "type": "object",
                "required": ["surfaces", "explicitExclusions", "deferred"],
                "properties": {
                    "surfaces": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["label", "disposition"],
                            "properties": {
                                "id": {"type": "string"},
                                "label": {"type": "string"},
                                "disposition": {
                                    "enum": [
                                        "reported",
                                        "no_issue_found",
                                        "rejected",
                                        "not_applicable",
                                        "needs_follow_up",
                                    ]
                                },
                                "notes": {"type": "string"},
                            },
                        },
                    },
                    "explicitExclusions": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["pattern", "reason"],
                            "properties": {"pattern": {"type": "string"}, "reason": {"type": "string"}},
                        },
                    },
                    "deferred": {"type": "array", "items": {"type": "object"}},
                    "resolvedDeferred": {"type": "array", "items": {"type": "object"}},
                    "openQuestions": {"type": "array", "items": {"type": "string"}},
                },
            },
        },
    },
}


def compact_mcp_schema_cache() -> dict[str, int]:
    stats = {"compacted_files": 0, "bytes_before": 0, "bytes_after": 0}
    MCP_CACHE_DIR.mkdir(parents=True, exist_ok=True)

    for json_file in sorted(MCP_CACHE_DIR.glob("*.json")):
        raw = json_file.read_bytes()
        stats["bytes_before"] += len(raw)
        if json_file.name == "record_agy_security_scan_draft.json":
            compacted = json.dumps(COMPACT_SCAN_DRAFT_SCHEMA, indent=2, ensure_ascii=False).encode("utf-8")
            json_file.write_bytes(compacted)
            stats["bytes_after"] += len(compacted)
            stats["compacted_files"] += 1
        else:
            try:
                parsed = json.loads(raw.decode("utf-8"))
                compacted = json.dumps(parsed, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                json_file.write_bytes(compacted)
                stats["bytes_after"] += len(compacted)
                stats["compacted_files"] += 1
            except Exception:
                stats["bytes_after"] += len(raw)
    return stats


def update_mcp_config() -> bool:
    MCP_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    MCP_STATE_DIR.mkdir(parents=True, exist_ok=True)
    cfg = {}
    if MCP_CONFIG_PATH.exists():
        try:
            cfg = json.loads(MCP_CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception:
            cfg = {}
    servers = cfg.setdefault("mcpServers", {})
    node_cmd = shutil.which("node") or "node"
    server = servers.setdefault(
        "agy_security",
        {
            "command": node_cmd,
            "args": [str(PLUGIN_ROOT / "mcp" / "server.mjs"), "--stdio"],
            "env": {},
        },
    )
    server["args"] = [str(PLUGIN_ROOT / "mcp" / "server.mjs"), "--stdio"]
    env = server.setdefault("env", {})
    env.pop("CODEX_SECURITY_PLUGIN_ROOT", None)
    env.pop("CODEX_SECURITY_STATE_DIR", None)
    env["AGY_SECURITY_PLUGIN_ROOT"] = str(PLUGIN_ROOT)
    env["AGY_SECURITY_STATE_DIR"] = str(MCP_STATE_DIR)
    env["AGY_SECURITY_KNOWLEDGE_BASE"] = str(KNOWLEDGE_DIR)
    env["PYTHON"] = sys.executable or "python"
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    MCP_CONFIG_PATH.write_text(json.dumps(cfg, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return True


def install_global_auto_trigger_rule() -> str:
    GLOBAL_RULES_DIR.mkdir(parents=True, exist_ok=True)
    rule_path = GLOBAL_RULES_DIR / "agy_security_auto_trigger.md"
    rule_path.write_text(AUTO_TRIGGER_RULE_CONTENT, encoding="utf-8")
    return str(rule_path)


def sync_skill_mirror() -> int:
    if SKILL_MIRROR_ROOT.resolve() == PLUGIN_ROOT.resolve():
        return 0
    SKILL_MIRROR_ROOT.mkdir(parents=True, exist_ok=True)
    master_skill = PLUGIN_ROOT / "skills" / "agy-security" / "SKILL.md"
    if master_skill.exists():
        shutil.copy2(master_skill, SKILL_MIRROR_ROOT / "SKILL.md")
    synced = 1
    for folder in ("agents", "knowledge", "references", "rules", "scripts", "mcp", "schemas", "skills"):
        src = PLUGIN_ROOT / folder
        dst = SKILL_MIRROR_ROOT / folder
        if src.exists():
            shutil.copytree(src, dst, dirs_exist_ok=True)
            synced += 1
    return synced


def main() -> int:
    knowledge_files = sorted(p.name for p in KNOWLEDGE_DIR.glob("*.md")) if KNOWLEDGE_DIR.exists() else []
    rule_path = install_global_auto_trigger_rule()
    schema_stats = compact_mcp_schema_cache()
    mcp_updated = update_mcp_config()
    synced_dirs = sync_skill_mirror()

    report = {
        "status": "installed",
        "pluginRoot": str(PLUGIN_ROOT),
        "knowledgeBaseDir": str(KNOWLEDGE_DIR),
        "knowledgeFiles": knowledge_files,
        "globalRuleInstalled": rule_path,
        "mcpSchemaCache": schema_stats,
        "mcpConfigUpdated": mcp_updated,
        "syncedSkillMirrorItems": synced_dirs,
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
