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

load("@score_baselibs//:bazel/unit_tests.bzl", "cc_unit_test_suites_for_host_and_qnx")

cc_library(
    name = "plugin",
    srcs = [],
    hdrs = ["plugin.h"],
    features = [
        "treat_warnings_as_errors",
        "strict_warnings",
        "additional_warnings",
    ],
    tags = ["FFI"],
    visibility = [
        "@score_config_management//score/config_management/config_daemon/code/app:__subpackages__",
        "@score_config_management//score/config_management/config_daemon/code/plugins:__subpackages__",
    ],
    deps = [
        "@score_baselibs//score/result",
        "@score_config_management//score/config_management/config_daemon/code/data_model:parameterset_collection",
        "@score_config_management//score/config_management/config_daemon/code/fault_event_reporter",
        "@score_config_management//score/config_management/config_daemon/code/services",
        "@score_baselibs//score/language/futurecpp",
    ],
)

cc_library(
    name = "mock",
    testonly = True,
    srcs = [],
    hdrs = ["plugin_mock.h"],
    features = [
        "treat_warnings_as_errors",
        "strict_warnings",
        "additional_warnings",
    ],
    visibility = [
        "@score_config_management//score/config_management/config_daemon/code/app:__subpackages__",
        "@score_config_management//score/config_management/config_daemon/code/plugins:__subpackages__",
    ],
    deps = [
        ":plugin",
        "@googletest//:gtest",
    ],
)

cc_library(
    name = "plugin_creator",
    srcs = [],
    hdrs = ["plugin_creator.h"],
    features = [
        "treat_warnings_as_errors",
        "strict_warnings",
        "additional_warnings",
    ],
    tags = ["FFI"],
    visibility = [
        "@score_config_management//score/config_management/config_daemon/code/plugins:__subpackages__",
    ],
)

cc_library(
    name = "plugin_creator_mock",
    testonly = True,
    srcs = [],
    hdrs = ["plugin_creator_mock.h"],
    features = [
        "treat_warnings_as_errors",
        "strict_warnings",
        "additional_warnings",
    ],
    visibility = [
        "@score_config_management//score/config_management/config_daemon/code/plugins:__subpackages__",
    ],
    deps = [
        ":plugin_creator",
        "@googletest//:gtest",
    ],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    test_suites_from_sub_packages = [
        "@score_config_management//score/config_management/config_daemon/code/plugins/calibration:unit_tests",
        "@score_config_management//score/config_management/config_daemon/code/plugins/coding:unit_tests",
        "@score_config_management//score/config_management/config_daemon/code/plugins/plugin_collector:unit_tests",
    ],
    visibility = ["@score_config_management//score/config_management/config_daemon/code:__pkg__"],
)
