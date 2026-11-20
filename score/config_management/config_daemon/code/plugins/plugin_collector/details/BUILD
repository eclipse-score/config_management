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

load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

[
    cc_library(
        name = name,
        testonly = testonly,
        srcs = ["plugin_collector_impl.cpp"],
        hdrs = [
            "plugin_collector_impl.h",
        ],
        features = COMPILER_WARNING_FEATURES,
        tags = ["FUSA"],
        visibility = [
            "//score/config_management/config_daemon/code:__subpackages__",
        ],
        deps = [
            "//score/config_management/config_daemon/code/plugins:plugin",
            "//score/config_management/config_daemon/code/plugins/plugin_collector:interface",
            "@score_baselibs//score/mw/log:frontend",
        ] + dependencies,
    )
    for name, testonly, dependencies in [
        (
            "details",
            False,
            [
                "//score/config_management/config_daemon/code/plugins:plugin_creator",
            ] + [
                "//score/config_management/config_daemon/code/plugins/demo_json/plugin_creator:demo_json_plugin_creator",
            ],
        ),
        (
            "details_for_unit_test",
            True,
            [
                "//score/config_management/config_daemon/code/plugins:mock",
                "//score/config_management/config_daemon/code/plugins:plugin_creator_mock",
            ] + [
                "//score/config_management/config_daemon/code/plugins/demo_json/plugin_creator:demo_json_plugin_creator",
            ],
        ),
    ]
]

cc_test(
    name = "unit_test",
    srcs = ["plugin_collector_impl_test.cpp"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["unit"],
    visibility = ["//score/config_management/config_daemon:__subpackages__"],
    deps = [
        ":details_for_unit_test",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
        "@score_baselibs//score/mw/log:console",
    ],
)
