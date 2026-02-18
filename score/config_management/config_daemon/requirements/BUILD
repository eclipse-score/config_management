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
    name = "safety_software_unit_config_daemon",
    # design = ["*.puml"],
    impl = ["@score_config_management//score/config_management/config_daemon/code:ConfigDaemon"],
    reqs = [
        "@score_config_management//score/config_management/config_daemon/requirements/component_requirements:component_requirements",
    ],
    tests = [
        "@score_config_management//score/config_management/config_daemon/code/app/details:unit_test",
    ],
)
