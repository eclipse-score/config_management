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

load("@score_tooling//bazel/rules/rules_score:rules_score.bzl", "feature_requirements")

feature_requirements(
    name = "feature_requirements",
    srcs = [
        "feature_requirements.trlc",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//requirements/assumed_system_requirements",
    ],
)
