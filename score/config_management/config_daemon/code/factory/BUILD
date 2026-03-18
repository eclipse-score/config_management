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

[
    cc_library(
        name = "interface" + name,
        testonly = testonly,
        srcs = [],
        hdrs = [
            "factory.h",
        ],
        features = COMPILER_WARNING_FEATURES,
        tags = ["FFI"],
        visibility = [
            "//score/config_management/config_daemon/code:__subpackages__",
        ],
        deps = [
            "@score_communication//score/mw/service",
            "//score/config_management/config_daemon/code/data_model:parameterset_collection",
            "//score/config_management/config_daemon/code/data_model:parameterset_collection_manager",
            "//score/config_management/config_daemon/code/data_model/parameter_set_storage",
            "//score/config_management/config_daemon/code/fault_event_reporter",
            "//score/config_management/config_daemon/code/plugins/plugin_collector:interface",
            "//score/config_management/config_daemon/code/services",
        ] + dependencies,
    )
    for name, testonly, dependencies in [
        (
            "",
            False,
            [],
        ),
        (
            "_for_unit_test",
            True,
            [],
        ),
    ]
]

cc_library(
    name = "mock",
    testonly = True,
    srcs = ["factory_mock.cpp"],
    hdrs = [
        "factory_mock.h",
    ],
    features = COMPILER_WARNING_FEATURES,
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        ":interface_for_unit_test",
        "//score/config_management/config_daemon/code/data_model:parameterset_collection",
        "//score/config_management/config_daemon/code/data_model:parameterset_collection_manager_mock",
        "//score/config_management/config_daemon/code/services:mock",
        "@googletest//:gtest",
    ],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [
        "//score/config_management/config_daemon/code/factory/details:unit_test_mw_com",
    ] + load_custom_test_suites(),
    visibility = ["//score/config_management/config_daemon:__subpackages__"],
)
