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
    "component",
    "dependable_element",
)

component(
    name = "config_daemon_component",
    components = [],
    requirements = ["//requirements/component_requirements/config_daemon:component_requirements"],
    tests = [],
    visibility = ["//visibility:public"],
)

component(
    name = "config_provider_component",
    components = [],
    requirements = ["//requirements/component_requirements/config_provider:component_requirements"],
    tests = [],
    visibility = ["//visibility:public"],
)

dependable_element(
    name = "config_management",
    architectural_design = ["//score/config_management/dependability/software_architectural_design:software_architectural_design"],
    assumptions_of_use = ["//requirements/safety_analysis:assumptions_of_use"],
    components = [
        ":config_daemon_component",
        ":config_provider_component",
    ],
    dependability_analysis = ["//requirements/safety_analysis:dependability_analysis"],
    integrity_level = "B",
    maturity = "development",
    requirements = [
        "//requirements/assumed_system_requirements:assumed_system_requirements",
        "//requirements/feature_requirements:feature_requirements",
    ],
    target_compatible_with = ["@platforms//os:linux"],
    tests = [],
    visibility = ["//visibility:public"],
)
