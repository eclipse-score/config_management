<!-- ----------------------------------------------------------------------------
  Copyright (c) 2026 Contributors to the Eclipse Foundation

  See the NOTICE file(s) distributed with this work for additional
  information regarding copyright ownership.

  This program and the accompanying materials are made available under the
  terms of the Apache License Version 2.0 which is available at
  https://www.apache.org/licenses/LICENSE-2.0

  SPDX-License-Identifier: Apache-2.0
----------------------------------------------------------------------------- -->

# Dependency Compatibility Checker

A config-driven tool that tests combinations of external dependency versions (and
Bazel versions) against the root `MODULE.bazel`, classifies each combination as
green / orange / red, and produces an HTML + JSON report.

In config_management it runs nightly (`.github/workflows/test_dependency_version_combinations.yml`)
and builds and tests `//score/config_management/...` against the latest releases and the `main`
branches of the score modules it depends on, so that a breaking API or build change in a
dependency shows up here before it reaches a release or the reference integration. The workflow
is a single job (one check): `run_combinations.py` runs the combinations one after the other and
produces one report (the `compatibility-report` artifact plus a table in the job summary).

The matrix strategy is set with the top-level key `strategy`:

- `cartesian` (default): every combination of the active versions.
- `one_at_a_time`: the first active version of each dependency is the baseline, and every
  further version is tried on its own against that baseline. The number of combinations grows
  linearly, which is what config_management uses.

## Config format (`config.yaml`)

`config.yaml` is the single source of truth for the matrix. It lists one entry per
dependency, each with the versions to test:

```yaml
strategy: one_at_a_time
dependencies:
  bazel:                       # special: drives USE_BAZEL_VERSION, not a MODULE dep
    versions:
      - version: "current"     # .bazelversion
  score_logging:
    remote: "https://github.com/eclipse-score/logging.git"
    versions:
      - version: "current"     # baseline: what MODULE.bazel uses
      - version: "latest"      # newest stable registry release, if newer
      - version: "main"        # head of main
        branch: "main"
        patches:
          - "//quality/dependency_compatibility_checker/patches:some.patch"
        patch_strip: 1
```

- Two keywords are resolved on every run by `resolve_config`, so the config does not have to be
  edited when a dependency releases:
  - `version: "current"` is what the root `MODULE.bazel` uses today (left untouched). It is
    labelled with the declared version, or `pinned` if an override pins the module. For
    `bazel` it is the version in `.bazelversion`. Use it as the first entry (the baseline).
  - `version: "latest"` is the newest stable release (no pre-release, no yanked version) in the
    score registry, falling back to the Bazel Central Registry. It is dropped unless it is
    newer than `current`, e.g. when `MODULE.bazel` already uses the latest release. It is not
    supported for `bazel`.
- A dependency that the root `MODULE.bazel` pins by commit (`git_override`) is described with a
  dependency-level `remote` and special version entries:
  - `keep: true` leaves the existing override untouched (use it for the baseline).
  - `commit: "<sha>"` tests that commit through a `git_override`.
  - `branch: "<name>"` tests the head of that branch, resolved with `git ls-remote` when the
    `MODULE.bazel` is rewritten.
  The `version` of such an entry is only a label that shows up in the report.
- `bazel` is a special pseudo-dependency: it drives `USE_BAZEL_VERSION` for the CI
  matrix instead of a `MODULE.bazel` override, and may not carry `patches` or
  `patch_strip`.
- Every other dependency key maps to a Bazel module (`module_name` defaults to the
  key; set it explicitly if the module name differs from the config key).
- Each version entry may optionally carry:
  - `patches` / `patch_strip` — applied via `single_version_override` whenever that
    version is selected.
  - `flags` — extra Bazel flags added for that version.
  - `skip: "<reason with ticket>"` — disables the version but keeps it in the file
    for traceability. A dependency must always have at least one non-skipped
    version.

## Commands

- **`run_combinations.py`** — what CI runs: resolves the config, expands the matrix, then for
  every combination rewrites `MODULE.bazel`, resolves, builds and tests, and finally renders the
  report. It refuses to start if `MODULE.bazel` or `MODULE.bazel.lock` have local changes,
  and restores both afterwards. The `rewrite` and `deps` stages are retried once, since they
  mostly fail on network errors. `--combinations 0,2` runs only some of them.

  ```bash
  python3 quality/dependency_compatibility_checker/run_combinations.py
  ```

- **`resolve_config`** — turns `config.yaml` into a plain config by replacing the `current` and
  `latest` keywords. The other tools below take this resolved config.

  ```bash
  bazel run //quality/dependency_compatibility_checker:resolve_config -- \
    --config "$PWD/quality/dependency_compatibility_checker/config.yaml" \
    --output /tmp/resolved_config.yaml
  ```

- **`generate_matrix`** — expands a (resolved) config into the matrix (one entry per
  combination of active versions) plus a list of skipped versions.

  ```bash
  bazel run //quality/dependency_compatibility_checker:generate_matrix -- \
    --config "$PWD/quality/dependency_compatibility_checker/config.yaml"
  ```

- **`module_rewriter`** — rewrites the root `MODULE.bazel` for one combination:
  removes any existing override block for each non-`bazel` dependency and appends a
  fresh `single_version_override(...)` (or `git_override(...)` for `commit`/`branch`
  entries), including `patches`/`patch_strip` when configured. Dependencies with a
  `keep` entry are left alone. Idempotent.

  ```bash
  bazel run //quality/dependency_compatibility_checker:module_rewriter -- \
    --module-file "$PWD/MODULE.bazel" \
    --config "$PWD/quality/dependency_compatibility_checker/config.yaml" \
    --combination-json '{"bazel":"8.7.0","rules_cc":"0.2.21","index":0,"has_patches":false,"flags":""}'
  ```

- **`generate_report`** — aggregates the per-combination result JSONs produced by CI
  into `report.html` and `summary.json`.

  ```bash
  bazel run //quality/dependency_compatibility_checker:generate_report -- \
    --results-dir <dir-of-result-jsons> \
    --config "$PWD/quality/dependency_compatibility_checker/config.yaml" \
    --output-dir <output-dir>
  ```

## Classification

| Build passes? | Patches configured for the combination? | Result   |
|---------------|-------------------------------------------|----------|
| yes           | no                                          | 🟢 green  |
| yes           | yes                                         | 🟠 orange |
| no            | any                                         | 🔴 red    |

- **green** — fully compatible, no patches required. Extra Bazel flags are allowed
  and do not downgrade a combination from green.
- **orange** — only compatible when the configured patches are applied.
- **red** — does not build at all.

Patches are always applied when configured; they are never applied reactively on
failure. Classification is a pure function of `(build_status, has_patches)`.

## Adding or skipping a version

- **New releases** need no change: `current` and `latest` are resolved on every run.
- **Add a dependency or a version:** add a new entry under `dependencies` or under the
  dependency's `versions` list in `config.yaml`, with `patches`/`patch_strip`/`flags` if
  needed. A dependency that is not listed is not tested.
- **Skip a version:** add `skip: "<reason with ticket>"` to the entry instead of
  deleting it, so the history stays visible. A dependency must keep at least one
  active (non-skipped) version.

## Running the tests

```bash
bazel test //quality/dependency_compatibility_checker/tests/... --test_output=errors
```
