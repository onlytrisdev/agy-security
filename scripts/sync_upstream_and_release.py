#!/usr/bin/env python3
"""Check upstream openai/codex-security commits for surgical review and build AGY Security release artifacts."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import subprocess
import tarfile
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
STATE_FILE = REPO_ROOT / "shared" / "upstream-sync-state.json"
PACKAGE_JSON = REPO_ROOT / "package.json"
PLUGIN_JSON = REPO_ROOT / "plugin.json"
UPSTREAM_REPO = "openai/codex-security"
TARGET_REPO = "onlytrisdev/agy-security"

PACKAGE_EXCLUDES = {
    ".git",
    ".github",
    "dist",
    "__pycache__",
    ".pytest_cache",
}


def github_get_json(url: str) -> Any:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "AGY-Security-Upstream-Inspector/1.0",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def load_state() -> dict[str, Any]:
    if STATE_FILE.is_file():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return {
        "agyVersion": "1.0.0",
        "upstreamRepository": UPSTREAM_REPO,
        "lastSyncedReleaseTag": None,
        "lastSyncedCommit": None,
        "lastCheckedAt": None,
    }


def save_state(state: dict[str, Any]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")


def get_agy_version() -> str:
    if PACKAGE_JSON.is_file():
        pkg = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))
        return str(pkg.get("version", "1.0.0"))
    return str(load_state().get("agyVersion", "1.0.0"))


def bump_semver(version: str, part: str) -> str:
    major, minor, patch = (int(x) for x in version.split(".")[:3])
    if part == "major":
        return f"{major + 1}.0.0"
    if part == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def set_agy_version(new_version: str) -> None:
    if PACKAGE_JSON.is_file():
        pkg = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))
        pkg["version"] = new_version
        PACKAGE_JSON.write_text(json.dumps(pkg, indent=2) + "\n", encoding="utf-8")
    if PLUGIN_JSON.is_file():
        plg = json.loads(PLUGIN_JSON.read_text(encoding="utf-8"))
        plg["version"] = new_version
        PLUGIN_JSON.write_text(json.dumps(plg, indent=2) + "\n", encoding="utf-8")
    state = load_state()
    state["agyVersion"] = new_version
    save_state(state)


def check_upstream() -> dict[str, Any]:
    state = load_state()
    releases = github_get_json(f"https://api.github.com/repos/{UPSTREAM_REPO}/releases?per_page=5")
    commits = github_get_json(f"https://api.github.com/repos/{UPSTREAM_REPO}/commits?per_page=15")

    latest_release = releases[0] if releases else {}
    latest_tag = latest_release.get("tag_name")
    latest_commit = commits[0]["sha"] if commits else None
    base_commit = state.get("lastSyncedCommit")

    changed_plugin_files: list[dict[str, Any]] = []
    changed_mcp_ts_files: list[str] = []
    changed_sdk_ts_files: list[str] = []
    commit_summaries: list[dict[str, Any]] = []

    if base_commit and latest_commit and base_commit != latest_commit:
        comparison = github_get_json(
            f"https://api.github.com/repos/{UPSTREAM_REPO}/compare/{base_commit}...{latest_commit}"
        )
        for commit in comparison.get("commits", []):
            commit_summaries.append(
                {
                    "sha": commit["sha"][:10],
                    "date": commit["commit"]["committer"]["date"],
                    "message": commit["commit"]["message"].splitlines()[0],
                }
            )
        for file_entry in comparison.get("files", []):
            filename = file_entry["filename"]
            if filename.startswith("plugins/codex-security/mcp-app/"):
                changed_mcp_ts_files.append(filename)
            elif filename.startswith("sdk/typescript/src/"):
                changed_sdk_ts_files.append(filename)
            elif (
                filename.startswith("plugins/codex-security/")
                and "/tests/" not in filename
                and not filename.endswith(".br")
            ):
                changed_plugin_files.append(
                    {
                        "filename": filename.removeprefix("plugins/codex-security/"),
                        "status": file_entry["status"],
                        "additions": file_entry["additions"],
                        "deletions": file_entry["deletions"],
                    }
                )

    return {
        "agyVersion": get_agy_version(),
        "upstreamRepository": UPSTREAM_REPO,
        "lastSyncedReleaseTag": state.get("lastSyncedReleaseTag"),
        "latestReleaseTag": latest_tag,
        "latestReleaseName": latest_release.get("name"),
        "latestReleasePublishedAt": latest_release.get("published_at"),
        "lastSyncedCommit": base_commit,
        "latestMainCommit": latest_commit,
        "hasNewRelease": bool(latest_tag and latest_tag != state.get("lastSyncedReleaseTag")),
        "hasNewCommits": bool(latest_commit and latest_commit != base_commit),
        "commitsSinceLastSync": commit_summaries,
        "changedPluginRuntimeFiles": changed_plugin_files,
        "changedMcpAppTypeScriptFiles": changed_mcp_ts_files,
        "changedSdkTypeScriptFiles": changed_sdk_ts_files,
        "reviewPolicy": (
            "1. Maintain independent AGY-Security semantic versioning (v1.x.y); NEVER copy upstream 0.x.y version numbers. "
            "2. NEVER create a version-bump-only commit or GitHub release if no real functional changes (scripts/, skills/, schemas/, shared/workbench-migrations.json, mcp/) were ported. "
            "3. Port real functional improvements across Python workbench, SQLite migrations, skills, and MCP SDK/runtime, and run full test suites before releasing."
        ),
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_release_artifacts(output_dir: Path) -> dict[str, Any]:
    version = get_agy_version()
    tag = f"v{version}"
    output_dir.mkdir(parents=True, exist_ok=True)

    tgz_name = f"agy-security-{version}.tgz"
    tgz_path = output_dir / tgz_name

    def _filter(tarinfo: tarfile.TarInfo) -> tarfile.TarInfo | None:
        parts = Path(tarinfo.name).parts
        if any(part in PACKAGE_EXCLUDES for part in parts):
            return None
        if tarinfo.name.endswith(".pyc"):
            return None
        return tarinfo

    with tarfile.open(tgz_path, "w:gz") as tar:
        for item in sorted(REPO_ROOT.iterdir(), key=lambda p: p.name):
            if item.name in PACKAGE_EXCLUDES:
                continue
            tar.add(item, arcname=f"package/{item.name}", filter=_filter)

    head_sha = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True
    ).strip()

    now_iso = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    tgz_sha256 = sha256_file(tgz_path)
    state = load_state()

    attestation = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": tgz_name,
                "digest": {"sha256": tgz_sha256},
            }
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/onlytrisdev/agy-security/release/v1",
                "externalParameters": {
                    "repository": f"https://github.com/{TARGET_REPO}",
                    "ref": f"refs/tags/{tag}",
                    "version": version,
                    "upstreamSource": f"https://github.com/{UPSTREAM_REPO}",
                    "upstreamSyncedCommit": state.get("lastSyncedCommit"),
                },
                "internalParameters": {
                    "architecture": "antigravity-2.0-mcp-plugin",
                },
                "resolvedDependencies": [
                    {
                        "uri": f"git+https://github.com/{TARGET_REPO}@refs/heads/main",
                        "digest": {"gitCommit": head_sha},
                    }
                ],
            },
            "runDetails": {
                "builder": {
                    "id": f"https://github.com/{TARGET_REPO}/actions/release-builder"
                },
                "metadata": {
                    "StartedOn": now_iso,
                    "FinishedOn": now_iso,
                },
            },
        },
    }

    attestation_path = output_dir / "release-attestation.json"
    attestation_path.write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")

    return {
        "version": version,
        "tag": tag,
        "title": f"AGY Security {version}",
        "commit": head_sha,
        "tarball": str(tgz_path),
        "tarballSha256": tgz_sha256,
        "attestation": str(attestation_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Check upstream status and list diffs for AI review.")
    parser.add_argument(
        "--bump-version",
        choices=["patch", "minor", "major"],
        help="Bump AGY Security's independent semantic version (only after porting real functional changes).",
    )
    parser.add_argument("--record-sync", metavar="COMMIT_SHA", help="Record that upstream commits up to COMMIT_SHA were reviewed and synced.")
    parser.add_argument("--release-tag", metavar="TAG", help="Optional upstream release tag to record with --record-sync.")
    parser.add_argument("--package", action="store_true", help="Build release tgz and attestation JSON.")
    parser.add_argument(
        "--out-dir",
        default=str(REPO_ROOT / "dist"),
        help="Output directory for release artifacts.",
    )
    args = parser.parse_args()

    result: dict[str, Any] = {}
    if args.check:
        result["check"] = check_upstream()
    if args.bump_version:
        new_ver = bump_semver(get_agy_version(), args.bump_version)
        set_agy_version(new_ver)
        result["bumpedVersion"] = new_ver
    if args.record_sync:
        state = load_state()
        state["agyVersion"] = get_agy_version()
        state["lastSyncedCommit"] = args.record_sync
        if args.release_tag:
            state["lastSyncedReleaseTag"] = args.release_tag
        state["lastCheckedAt"] = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        save_state(state)
        result["recordedState"] = state
    if args.package:
        result["package"] = build_release_artifacts(Path(args.out_dir))

    if not result:
        result["check"] = check_upstream()

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
