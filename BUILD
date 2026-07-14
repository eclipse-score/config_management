# *******************************************************************************
# Copyright (c) 2025 Contributors to the Eclipse Foundation
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

load("@score_tooling//:defs.bzl", "copyright_checker", "dash_license_checker", "setup_starpls", "use_format_targets")
load("//:project_config.bzl", "PROJECT_CONFIG")

setup_starpls(
    name = "starpls_server",
    visibility = ["//visibility:public"],
)

copyright_checker(
    name = "copyright",
    srcs = [
        "src",
        "tests",
        "//:BUILD",
        "//:MODULE.bazel",
    ],
    config = "@score_tooling//cr_checker/resources:config",
    template = "@score_tooling//cr_checker/resources:templates",
    visibility = ["//visibility:public"],
)

dash_license_checker(
    src = "//examples:cargo_lock",
    file_type = "",  # let it auto-detect based on project_config
    project_config = PROJECT_CONFIG,
    visibility = ["//visibility:public"],
)

# Add target for formatting checks
use_format_targets()

# Compatibility shim: the cicd-workflows reusable docs.yml calls
# `bazel run //:docs`. sphinx_module targets are not runnable, so this
# alias points to //build_docs:runner which copies the pre-built sphinx_doc
# HTML from runfiles into _build/html/ for the reusable workflow to deploy.
alias(
    name = "docs",
    testonly = True,
    actual = "//build_docs:runner",
)
