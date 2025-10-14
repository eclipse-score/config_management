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

load("@score-baselibs//:bazel/unit_tests.bzl", "cc_unit_test_suites_for_host_and_qnx")

COMMON_FEATURES = [
    "treat_warnings_as_errors",
    "strict_warnings",
    "additional_warnings",
]

cc_library(
    name = "interface",
    testonly = False,
    srcs = [],
    hdrs = [
        "plugin_collector.h",
    ],
    features = COMMON_FEATURES,
    tags = ["FFI"],
    visibility = [
        "@score-config_management//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        "@score-config_management//score/config_management/config_daemon/code/plugins:plugin",
    ],
)

cc_library(
    name = "mock",
    testonly = True,
    srcs = [],
    hdrs = [
        "plugin_collector_mock.h",
    ],
    features = COMMON_FEATURES,
    visibility = [
        "@score-config_management//score/config_management/config_daemon:__subpackages__",
    ],
    deps = [],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [
        "@score-config_management//score/config_management/config_daemon/code/plugins/plugin_collector/details:unit_test",
    ],
    visibility = ["@score-config_management//score/config_management/config_daemon:__subpackages__"],
)
