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

load(
    "@score_tooling//bazel/rules/rules_score:rules_score.bzl",
    "assumptions_of_use",
    "dependability_analysis",
    "fault_trees",
    "safety_analysis",
)

assumptions_of_use(
    name = "assumptions_of_use",
    srcs = ["aou.trlc"],
    visibility = ["//visibility:public"],
)

# No failure modes / fault trees are modelled yet; the AoUs are attached through the safety analysis.
fault_trees(
    name = "fault_trees",
)

safety_analysis(
    name = "safety_analysis",
    fault_trees = ":fault_trees",
    safety_measures = [":assumptions_of_use"],
)

dependability_analysis(
    name = "dependability_analysis",
    arch_design = "//score/config_management/dependability/software_architectural_design:software_architectural_design",
    safety_analysis = [":safety_analysis"],
    visibility = ["//visibility:public"],
)
