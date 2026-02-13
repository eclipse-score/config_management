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
load("//third_party/traceability/bazel:traceability.bzl", "safety_software_unit")

safety_software_unit(
    name = "safety_software_unit_config_provider",
    # design = ["*.puml"],
    impl = ["//score/config_management/config_provider:ConfigProvider_r20_11"],
    reqs = [
        "//score/config_management/config_provider/requirements/component_requirements:component_requirements",
    ],
    tests = [
        "//score/config_management/config_provider/code/config_provider/details:unit_test",
    ],
)
