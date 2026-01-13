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
        "factory.h",
        "service_container_selector.h",
    ] + select({
        "@score_config_management//score/config_management/config_daemon/code:is_score_variant": ["stub_service_container.h"],
        "//conditions:default": [],
    }),
    defines = select({
        "@score_config_management//score/config_management/config_daemon/code:is_score_variant": ["SCORE_BUILD"],
        "//conditions:default": [],
    }),
    features = COMMON_FEATURES,
    tags = ["FFI"],
    visibility = [
        "@score_config_management//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        "@score_config_management//score/config_management/config_daemon/code/data_model:parameterset_collection",
        "@score_config_management//score/config_management/config_daemon/code/fault_event_reporter",
        "@score_config_management//score/config_management/config_daemon/code/plugins/plugin_collector:interface",
        "@score_config_management//score/config_management/config_daemon/code/services",
    ] + select({
        "@score_config_management//score/config_management/config_daemon/code:is_score_variant": [],
        "//conditions:default": ["@score_communication//score/mw/service"],
    }),
)

cc_library(
    name = "mock",
    testonly = True,
    srcs = ["factory_mock.cpp"],
    hdrs = [
        "factory_mock.h",
    ],
    features = COMMON_FEATURES,
    visibility = [
        "@score_config_management//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        ":interface",
        "@score_config_management//score/config_management/config_daemon/code/data_model:parameterset_collection",
        "@score_config_management//score/config_management/config_daemon/code/services:mock",
        "@googletest//:gtest",
    ],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [
        "@score_config_management//score/config_management/config_daemon/code/factory/details:unit_test_ara_com",
        #"@score_config_management//score/config_management/config_daemon/code/factory/details:unit_test_mw_com",
    ],
    visibility = ["@score_config_management//score/config_management/config_daemon:__subpackages__"],
)
