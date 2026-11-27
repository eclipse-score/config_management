# *******************************************************************************
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
# *******************************************************************************
"""Replace the `current` and `latest` version keywords of a config by concrete versions.

- `current` keeps whatever the root MODULE.bazel uses today (no rewrite). It is labelled with
  the declared bazel_dep version, or `pinned` if the module is pinned by an override.
  For `bazel` it is the version in .bazelversion.
- `latest` is the newest stable release listed in the Bazel registries. It is dropped unless it
  is newer than `current`.

The resolved config is a plain config that generate_matrix, module_rewriter and generate_report
consume unchanged.
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import yaml

from quality.dependency_compatibility_checker import config_schema
from quality.dependency_compatibility_checker import module_rewriter

CURRENT = "current"
LATEST = "latest"
PINNED = "pinned"

DEFAULT_REGISTRIES = (
    "https://raw.githubusercontent.com/eclipse-score/bazel_registry/main",
    "https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/main",
)

_STABLE_VERSION = re.compile(r"^\d+(\.\d+)*(\.bcr\.\d+)?$")
_PINNING_OVERRIDES = ("git_override", "archive_override", "local_path_override")


def _fetch_json(url: str, attempts: int = 3):
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as err:
            if err.code == 404:
                return None
            transient = err.code >= 500 or err.code == 429
            if not transient or attempt == attempts:
                raise
        except (urllib.error.URLError, TimeoutError):
            if attempt == attempts:
                raise
        time.sleep(2**attempt)


def _sort_key(version: str):
    return tuple(int(part) for part in re.findall(r"\d+", version))


def latest_release(
    module_name, registries=DEFAULT_REGISTRIES, fetch=_fetch_json
) -> str:
    """Newest stable, non-yanked version of `module_name` in the first registry that has it."""
    for registry in registries:
        metadata = fetch(f"{registry}/modules/{module_name}/metadata.json")
        if not metadata:
            continue
        yanked = set(metadata.get("yanked_versions") or {})
        stable = [
            v
            for v in metadata.get("versions", [])
            if v not in yanked and _STABLE_VERSION.match(v)
        ]
        if stable:
            return max(stable, key=_sort_key)
    raise ValueError(f"{module_name}: no stable release found in {list(registries)}")


def current_version(module_text: str, module_name: str) -> str:
    """Label of what MODULE.bazel uses for `module_name`: a version, or `pinned`."""
    lines = module_text.splitlines()
    name_re = re.compile(
        r"""\bmodule_name\s*=\s*['"]""" + re.escape(module_name) + r"""['"]"""
    )
    starts_re = re.compile(r"^\s*(\w+_override)\s*\(")
    version_re = re.compile(r"""\bversion\s*=\s*['"]([^'"]+)['"]""")
    i = 0
    while i < len(lines):
        match = (
            None if module_rewriter.is_comment(lines[i]) else starts_re.match(lines[i])
        )
        if match:
            end = module_rewriter.block_end(lines, i)
            body = [
                ln for ln in lines[i : end + 1] if not module_rewriter.is_comment(ln)
            ]
            if any(name_re.search(ln) for ln in body):
                if match.group(1) in _PINNING_OVERRIDES:
                    return PINNED
                for ln in body:
                    found = version_re.search(ln)
                    if found:
                        return found.group(1)
            i = end
        i += 1

    dep_re = re.compile(
        r"""bazel_dep\s*\(\s*name\s*=\s*['"]"""
        + re.escape(module_name)
        + r"""['"][^)]*?\bversion\s*=\s*['"]([^'"]+)['"]"""
    )
    code = "\n".join(ln for ln in lines if not module_rewriter.is_comment(ln))
    found = dep_re.search(code)
    if not found:
        raise ValueError(f"{module_name}: no bazel_dep with a version in MODULE.bazel")
    return found.group(1)


def _not_newer(version: str, current) -> bool:
    if current is None or not re.search(r"\d", current):
        return False
    return _sort_key(version) <= _sort_key(current)


def resolve(
    raw: dict,
    module_text: str,
    registries=DEFAULT_REGISTRIES,
    fetch=_fetch_json,
    bazel_version=None,
):
    """Return a copy of the raw config with the version keywords replaced."""
    resolved = json.loads(json.dumps(raw))
    for key, dep in resolved["dependencies"].items():
        is_bazel = key == config_schema.BAZEL_KEY
        module_name = str(dep.get("module_name") or key)
        current = None
        if any(str(e["version"]) == CURRENT for e in dep["versions"]):
            if not is_bazel:
                current = current_version(module_text, module_name)
            elif bazel_version:
                current = bazel_version
            else:
                raise ValueError(f"bazel: '{CURRENT}' needs a .bazelversion file")
        entries = []
        seen = set()
        for entry in dep["versions"]:
            version = str(entry["version"])
            if version == CURRENT:
                if entry.get("patches") or entry.get("flags"):
                    raise ValueError(
                        f"{key}: '{CURRENT}' cannot carry patches or flags"
                    )
                entry["version"] = current
                if not is_bazel:
                    entry["keep"] = True
            elif version == LATEST:
                if is_bazel:
                    raise ValueError(f"bazel: '{LATEST}' is not supported")
                entry["version"] = latest_release(module_name, registries, fetch)
                if _not_newer(entry["version"], current):
                    print(
                        f"{key}: latest is {entry['version']}, not newer than "
                        f"current {current}; dropped"
                    )
                    continue
            if entry["version"] in seen:
                print(
                    f"{key}: {version} is {entry['version']}, already covered; dropped"
                )
                continue
            seen.add(entry["version"])
            entries.append(entry)
        dep["versions"] = entries
    return resolved


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument(
        "--module-file",
        default=os.path.join(
            os.environ.get("BUILD_WORKSPACE_DIRECTORY", "."), "MODULE.bazel"
        ),
    )
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--registry", action="append", help="registry base URL (repeatable)"
    )
    args = parser.parse_args(argv)

    raw = yaml.safe_load(Path(args.config).read_text(encoding="utf-8"))
    module_file = Path(args.module_file)
    module_text = module_file.read_text(encoding="utf-8")
    bazelversion = module_file.parent / ".bazelversion"
    bazel_version = (
        bazelversion.read_text(encoding="utf-8").strip()
        if bazelversion.exists()
        else None
    )
    resolved = resolve(
        raw,
        module_text,
        tuple(args.registry or DEFAULT_REGISTRIES),
        bazel_version=bazel_version,
    )
    output = Path(args.output)
    output.write_text(
        "# Generated by resolve_config from config.yaml; do not edit.\n"
        + yaml.safe_dump(resolved, sort_keys=False),
        encoding="utf-8",
    )
    config_schema.load_config(output)  # fail early on an invalid result
    for key, dep in resolved["dependencies"].items():
        print(f"{key}: {', '.join(str(v['version']) for v in dep['versions'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
