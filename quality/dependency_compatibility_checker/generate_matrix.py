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

"""Expand the compatibility config into a GitHub Actions matrix (JSON on stdout)."""

import argparse
import itertools
import json
import os
import sys

from quality.dependency_compatibility_checker import config_schema

_DEFAULT_CONFIG = os.path.join(os.path.dirname(__file__), "config.yaml")


def _dedup(items):
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def build_matrix(config_path) -> dict:
    cfg = config_schema.load_config(config_path)

    skipped = [
        {"dependency": dep.key, "version": v.version, "reason": v.skip}
        for dep in cfg.dependencies
        for v in dep.versions
        if v.skip is not None
    ]

    per_dep_choices = [
        [(dep, v) for v in dep.active_versions] for dep in cfg.dependencies
    ]

    if cfg.strategy == "one_at_a_time":
        # Baseline (first active version of every dependency) plus one combination per
        # additional version, so the matrix grows linearly with the number of versions.
        baseline = [choices[0] for choices in per_dep_choices]
        selections = [baseline]
        for position, choices in enumerate(per_dep_choices):
            for choice in choices[1:]:
                selections.append(
                    baseline[:position] + [choice] + baseline[position + 1 :]
                )
    else:
        selections = itertools.product(*per_dep_choices)

    include = []
    for index, selection in enumerate(selections):
        combo = {"index": index}
        patches = []
        flags = []
        for dep, entry in selection:
            combo[dep.key] = entry.version
            patches.extend(entry.patches)
            flags.extend(entry.flags)
        combo["has_patches"] = bool(patches)
        combo["flags"] = " ".join(_dedup(flags))
        include.append(combo)

    return {"include": include, "skipped": skipped}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=_DEFAULT_CONFIG)
    args = parser.parse_args(argv)
    # GitHub Actions reads this as strategy.matrix, which only understands `include`.
    # `skipped` is intentionally NOT emitted here (generate_report reads skip info
    # straight from the config); emitting it would create a spurious matrix axis.
    result = build_matrix(args.config)
    json.dump({"include": result["include"]}, sys.stdout, separators=(",", ":"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
