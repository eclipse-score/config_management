# *******************************************************************************
# Copyright (c) 2024 Contributors to the Eclipse Foundation
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

load(
    "@score_tooling//bazel/rules/rules_score:rules_score.bzl",
    "assumptions_of_use",
    "dependability_analysis",
    "fmea",
)
load("@trlc//:trlc.bzl", "trlc_requirements")

# Failure Modes
fmea(
    name = "fmea",
    failuremodes = ["failure_modes.trlc"],
    visibility = ["//visibility:public"],
)

# Assumptions of Use: wrap aou.trlc to provide TrlcProviderInfo for assumptions_of_use
trlc_requirements(
    name = "aou_trlc",
    srcs = [
        "aou.trlc",
    ],
    spec = [
        "@score_tooling//bazel/rules/rules_score/trlc/config:score_requirements_model",
    ],
    visibility = ["//visibility:public"],
)

assumptions_of_use(
    name = "assumptions_of_use",
    srcs = [":aou_trlc"],
    visibility = ["//visibility:public"],
)

dependability_analysis(
    name = "dependability_analysis",
    fmea = [":fmea"],
    visibility = ["//visibility:public"],
)
