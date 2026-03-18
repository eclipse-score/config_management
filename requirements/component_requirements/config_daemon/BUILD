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

trlc_requirements(
    name = "component_requirements",
    srcs = [
        "component_requirements.trlc",
        "//requirements/assumed_system_requirements",
        "//requirements/feature_requirements",
    ],
    spec = [
        "//third_party/traceability/config/trlc/score_model:requirement_metamodel",
    ],
    visibility = ["//visibility:public"],
)

trlc_requirements_test(
    name = "component_requirements_test",
    reqs = [
        ":component_requirements",
    ],
    visibility = ["//visibility:public"],
)
