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
            "@score_logging//score/mw/log",
            "//score/config_management/config_daemon/code/plugins:plugin",
            "//score/config_management/config_daemon/code/plugins/plugin_collector:interface",
        ] + dependencies,
    )
    for name, testonly, dependencies in [
        (
            "details",
            False,
            [
                "//score/config_management/config_daemon/code/plugins:plugin_creator",
            ] + select({
                "//score/config_management/config_daemon/code:is_score_variant": [
                    "//score/config_management/config_daemon/code/plugins/demo_json/plugin_creator:demo_json_plugin_creator",
                ],
                "//conditions:default": [
                    "//score/config_management/config_daemon/code/plugins/coding/plugin_creator:coding_plugin_creator",
                    "//score/config_management/config_daemon/code/plugins/calibration/plugin_creator:calibration_plugin_creator",
                ],
            }),
        ),
        (
            "details_for_unit_test",
            True,
            [
                "//score/config_management/config_daemon/code/plugins:mock",
                "//score/config_management/config_daemon/code/plugins:plugin_creator_mock",
            ] + select({
                "//score/config_management/config_daemon/code:is_score_variant": [
                    "//score/config_management/config_daemon/code/plugins/demo_json/plugin_creator:demo_json_plugin_creator",
                ],
                "//conditions:default": [
                    "//score/config_management/config_daemon/code/plugins/coding/plugin_creator:coding_plugin_creator_for_unit_test",
                    "//score/config_management/config_daemon/code/plugins/calibration/plugin_creator:calibration_plugin_creator_for_unit_test",
                    "//score/config_management/config_daemon/code/plugins/calibration/details:calibration_impl_for_test",
                    "//score/config_management/config_daemon/code/plugins/calibration/factory/details:factory_impl_for_test",
                ],
            }),
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
        "@score_logging//score/mw/log/test/console_logging_environment",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)
