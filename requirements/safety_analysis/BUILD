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

load("@trlc//:trlc.bzl", "trlc_requirements", "trlc_requirements_test")

# Failures Modes
trlc_requirements(
    name = "failure_modes",
    srcs = [
        "failure_modes.trlc",
    ],
    spec = [
        "@score_tooling//bazel/rules/rules_score/trlc/config:score_requirements_model",
    ],
    visibility = ["//visibility:public"],
)

trlc_requirements_test(
    name = "failure_modes_test",
    reqs = [
        ":failure_modes",
    ],
    visibility = ["//visibility:public"],
)

# AoUs
trlc_requirements(
    name = "control_measures",
    srcs = [
        "aou.trlc",
    ],
    spec = [
        "@score_tooling//bazel/rules/rules_score/trlc/config:score_requirements_model",
    ],
    visibility = ["//visibility:public"],
)

trlc_requirements_test(
    name = "control_measures_test",
    reqs = [
        ":control_measures",
    ],
    visibility = ["//visibility:public"],
)
