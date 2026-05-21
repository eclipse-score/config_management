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

load("@rules_cc//cc:defs.bzl", "cc_library")
load("@score_baselibs//:bazel/unit_tests.bzl", "cc_unit_test_suites_for_host_and_qnx")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")
load(":custom.bzl", "load_custom_test_suites")

cc_library(
    name = "services",
    srcs = [
        "internal_config_provider_service.cpp",
    ],
    hdrs = [
        "internal_config_provider_service.h",
    ],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FUSA"],
    visibility = ["//score/config_management/config_daemon:__subpackages__"],
    deps = [
        "//score/config_management/config_daemon/code/types/initial_qualifier_state",
        "@score_baselibs//score/language/futurecpp",
        "@score_communication//score/mw/service:provided_service_container",
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
    features = COMPILER_WARNING_FEATURES,
    visibility = ["//score/config_management/config_daemon/code:__subpackages__"],
    deps = [
        ":services",
        "@googletest//:gtest",
    ],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [
        "//score/config_management/config_daemon/code/services/details:unit_test",
    ] + load_custom_test_suites(),
    visibility = ["//score/config_management/config_daemon:__subpackages__"],
)

cc_library(
    name = "internal_config_provider_reactor",
    srcs = ["internal_config_provider_service_reactor.cpp"],
    hdrs = ["internal_config_provider_service_reactor.h"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FUSA"],
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        "@score_baselibs//score/language/futurecpp",
        "@score_baselibs//score/result",
    ],
)

cc_library(
    name = "internal_config_provider_reactor_mock",
    testonly = True,
    srcs = ["internal_config_provider_service_reactor_mock.cpp"],
    hdrs = ["internal_config_provider_service_reactor_mock.h"],
    features = COMPILER_WARNING_FEATURES,
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        ":internal_config_provider_reactor",
        "@googletest//:gtest",
    ],
)
