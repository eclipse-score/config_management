#!/usr/bin/env bash
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
#
# Compatibility shim: makes `bazel run //:docs` work with sphinx_module output.
#
# The cicd-workflows reusable docs.yml calls `bazel run //:docs` and expects
# HTML in _build/html/. sphinx_module targets are not runnable, so this script
# copies the pre-built sphinx_doc HTML from bazel-bin/ into _build/html/.
#
# //docs/sphinx:sphinx_doc is a data dependency so Bazel always builds it first.
# Any extra arguments (e.g. --github_user, --github_repo) are silently ignored.
set -euo pipefail

# BUILD_WORKSPACE_DIRECTORY is set by `bazel run` to the workspace root.
WORKSPACE="${BUILD_WORKSPACE_DIRECTORY:-$(pwd)}"
HTML_SRC="${WORKSPACE}/bazel-bin/docs/sphinx/sphinx_doc/html"
HTML_DST="${WORKSPACE}/_build"

if [[ ! -d "${HTML_SRC}" ]]; then
    echo "ERROR: sphinx_doc HTML not found at ${HTML_SRC}" >&2
    exit 1
fi

# Fix read-only Bazel output permissions before removing
[[ -d "${HTML_DST}" ]] && chmod -R u+w "${HTML_DST}" && rm -rf "${HTML_DST}"
mkdir -p "${HTML_DST}"
# Copy HTML contents directly into _build/ so index.html lands at the root.
# The cicd-workflows deploy-versioned-pages action serves source_folder=_build
# at https://.../pr-N/ — a nested _build/html/ sub-dir would cause 404.
cp -r "${HTML_SRC}/." "${HTML_DST}/"
# Fix permissions so the tar step in the workflow can read all files
chmod -R u+w "${HTML_DST}"
echo "Documentation written to ${HTML_DST}"
