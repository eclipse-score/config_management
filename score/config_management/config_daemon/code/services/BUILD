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
    name = "services",
    srcs = [
        "internal_config_provider_service.cpp",
    ],
    hdrs = [
        "internal_config_provider_service.h",
    ],
    features = COMMON_FEATURES,
    tags = ["FUSA"],
    visibility = ["@score_config_management//score/config_management/config_daemon:__subpackages__"],
    deps = [
        "@score_communication//score/mw/service:provided_service_container",
        "@score_config_management//score/config_management/config_daemon/code/types/initial_qualifier_state",
        "@score_baselibs//score/language/futurecpp",
    ],
)

cc_library(
    name = "mock",
    testonly = True,
    srcs = [
        "internal_config_provider_service_mock.cpp",
    ],
    hdrs = [
        "internal_config_provider_service_mock.h",
    ],
    features = COMMON_FEATURES,
    visibility = ["@score_config_management//score/config_management/config_daemon/code:__subpackages__"],
    deps = [
        ":services",
        "@googletest//:gtest",
    ],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [
        "@score_config_management//score/config_management/config_daemon/code/services/details:unit_tests_mw_com",
        #"@score_config_management//score/config_management/config_daemon/code/services/details:unit_tests_mw_com",
    ],
    visibility = ["@score_config_management//score/config_management/config_daemon:__subpackages__"],
)

cc_library(
    name = "internal_config_provider_reactor",
    srcs = ["internal_config_provider_service_reactor.cpp"],
    hdrs = ["internal_config_provider_service_reactor.h"],
    features = COMMON_FEATURES,
    tags = ["FUSA"],
    visibility = [
        "@score_config_management//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        "@score_baselibs//score/result",
        "@score_baselibs//score/language/futurecpp",
    ],
)

cc_library(
    name = "internal_config_provider_reactor_mock",
    testonly = True,
    srcs = ["internal_config_provider_service_reactor_mock.cpp"],
    hdrs = ["internal_config_provider_service_reactor_mock.h"],
    features = COMMON_FEATURES,
    visibility = [
        "@score_config_management//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        ":internal_config_provider_reactor",
        "@googletest//:gtest",
    ],
)
