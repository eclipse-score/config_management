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
"""Build and test every dependency version combination in one run and render one report.

Run it with a plain python3 from a clean checkout (it rewrites and restores MODULE.bazel):

    python3 quality/dependency_compatibility_checker/run_combinations.py
"""

import argparse
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

CHECKER = "//quality/dependency_compatibility_checker"
TARGETS = [
    "//score/config_management/...",
    "-//score/config_management/dependability/...",
]
MODULE_FILES = ["MODULE.bazel", "MODULE.bazel.lock"]
_NOT_A_DEPENDENCY = ("index", "has_patches", "flags")
# Stages that mostly fail on network hiccups (registry, git ls-remote, downloads).
_ATTEMPTS = {"rewrite": 2, "deps": 2}


def _restore_module_files(root: Path) -> None:
    subprocess.run(["git", "checkout", "-q", "--", *MODULE_FILES], cwd=root, check=True)


def _local_module_changes(root: Path) -> str:
    return subprocess.run(
        ["git", "status", "--porcelain", "--", *MODULE_FILES],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _bazel_run(tool: str, *tool_args: str, capture: bool = False):
    cmd = [
        "bazel",
        "run",
        "--ui_event_filters=-info,-stdout",
        "--noshow_progress",
        "--lockfile_mode=off",
        f"{CHECKER}:{tool}",
        "--",
        *tool_args,
    ]
    return subprocess.run(cmd, check=True, text=True, capture_output=capture)


def _run_logged(cmd, log, env) -> int:
    """Run `cmd`, echoing its output to the console and appending it to `log`."""
    print("+", shlex.join(cmd), flush=True)
    with open(log, "a", encoding="utf-8") as sink:
        sink.write(f"+ {shlex.join(cmd)}\n")
        proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
        )
        for line in proc.stdout:
            sys.stdout.write(line)
            sink.write(line)
        return proc.wait()


def _run_combination(combo: dict, root: Path, resolved: Path, out: Path) -> dict:
    index = combo["index"]
    log = out / f"log-{index}.txt"
    log.write_text("", encoding="utf-8")
    env = {**os.environ, "USE_BAZEL_VERSION": combo["bazel"]}
    flags = shlex.split(combo.get("flags", ""))
    stages = [
        (
            "rewrite",
            [
                "bazel",
                "run",
                "--lockfile_mode=off",
                f"{CHECKER}:module_rewriter",
                "--",
                "--module-file",
                str(root / "MODULE.bazel"),
                "--config",
                str(resolved),
                "--combination-json",
                json.dumps(combo),
            ],
        ),
        ("deps", ["bazel", "mod", "deps", "--lockfile_mode=off"]),
        (
            "build",
            [
                "bazel",
                "build",
                "--config=host_gcc",
                "--lockfile_mode=off",
                "--keep_going",
                *flags,
                "--",
                *TARGETS,
            ],
        ),
        (
            "test",
            [
                "bazel",
                "test",
                "--config=host_gcc",
                "--lockfile_mode=off",
                "--keep_going",
                "--build_tests_only",
                *flags,
                "--",
                *TARGETS,
            ],
        ),
    ]

    versions = {k: v for k, v in combo.items() if k not in _NOT_A_DEPENDENCY}
    print(f"::group::combination {index}: {versions}", flush=True)
    failed_stage = ""
    for name, cmd in stages:
        for attempt in range(1, _ATTEMPTS.get(name, 1) + 1):
            with open(log, "a", encoding="utf-8") as sink:
                sink.write(f"===== STAGE: {name} (attempt {attempt}) =====\n")
            if name == "rewrite":
                _restore_module_files(root)
            rc = _run_logged(cmd, log, env)
            if rc == 0:
                break
        if rc != 0:
            failed_stage = name
            with open(log, "a", encoding="utf-8") as sink:
                sink.write(f"===== STAGE {name} FAILED (rc={rc}) =====\n")
            break
    print("::endgroup::", flush=True)
    if failed_stage:
        print(
            f"::error::combination {index} failed at stage: {failed_stage}", flush=True
        )

    result = {
        "index": index,
        "versions": versions,
        "build_status": "failure" if failed_stage else "success",
        "has_patches": bool(combo.get("has_patches", False)),
        "failed_stage": failed_stage,
    }
    (out / f"result-{index}.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8"
    )
    return result


def _write_step_summary(results: list) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path or not results:
        return
    deps = list(results[0]["versions"])
    baseline = results[0]["versions"]
    rows = [
        "## Dependency compatibility",
        "",
        "| # | " + " | ".join(deps) + " | result |",
    ]
    rows.append("|---|" + "---|" * (len(deps) + 1))
    for res in results:
        cells = [
            f"**{res['versions'][d]}**"
            if res["versions"][d] != baseline[d]
            else str(res["versions"][d])
            for d in deps
        ]
        if res["build_status"] != "success":
            status = f"red ({res['failed_stage']})"
        else:
            status = "orange" if res["has_patches"] else "green"
        rows.append(f"| {res['index']} | " + " | ".join(cells) + f" | {status} |")
    rows += [
        "",
        "Bold: differs from the baseline (combination 0). Full report: the `compatibility-report` artifact.",
    ]
    with open(path, "a", encoding="utf-8") as sink:
        sink.write("\n".join(rows) + "\n")


def main(argv=None) -> int:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config", default=str(Path(__file__).with_name("config.yaml"))
    )
    parser.add_argument("--output-dir", default=str(root / "matrix-results"))
    parser.add_argument(
        "--combinations", help="comma separated indices to run (default: all)"
    )
    args = parser.parse_args(argv)

    os.chdir(root)
    changes = _local_module_changes(root)
    if changes:
        print(
            "::error::MODULE.bazel or MODULE.bazel.lock has local changes, which this "
            f"tool would overwrite. Commit or stash them first:\n{changes}"
        )
        return 2
    out = Path(args.output_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    for stale in [*out.glob("result-*.json"), *out.glob("log-*.txt")]:
        stale.unlink()
    resolved = out / "resolved_config.yaml"

    _bazel_run(
        "resolve_config",
        "--config",
        str(Path(args.config).resolve()),
        "--module-file",
        str(root / "MODULE.bazel"),
        "--output",
        str(resolved),
    )
    matrix = json.loads(
        _bazel_run("generate_matrix", "--config", str(resolved), capture=True).stdout
    )["include"]
    selected = (
        {int(i) for i in args.combinations.split(",")} if args.combinations else None
    )

    results = []
    try:
        for combo in matrix:
            if selected is None or combo["index"] in selected:
                results.append(_run_combination(combo, root, resolved, out))
    finally:
        _restore_module_files(root)

    _bazel_run(
        "generate_report",
        "--results-dir",
        str(out),
        "--config",
        str(resolved),
        "--output-dir",
        str(out),
        "--fail-on",
        "never",
    )
    _write_step_summary(results)

    red = [r for r in results if r["build_status"] != "success"]
    if red:
        print(f"::error::{len(red)} combination(s) failed to build (red)")
        return 1
    print("No red combinations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
