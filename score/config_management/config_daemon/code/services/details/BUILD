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
        srcs = [
            "internal_config_provider_service_reactor_impl.cpp",
        ],
        hdrs = [
            "internal_config_provider_service_reactor_impl.h",
        ],
        features = COMPILER_WARNING_FEATURES,
        tags = ["FUSA"],
        visibility = [
            "//score/config_management/config_daemon/code:__subpackages__",
        ],
        deps = [
            "//score/config_management/config_daemon/code/data_model/parameterset_collection_interfaces:read_only_parameterset_collection",
            "@score_logging//score/mw/log",
        ] + dependencies,
    )
    for name, testonly, dependencies in [
        (
            "details_impl",
            False,
            [
                "@score_baselibs//score/result",
                "@score_communication//score/mw/com",
                "//score/config_management/config_daemon/code/services:internal_config_provider_reactor",
            ],
        ),
        (
            "for_unit_test",
            True,
            [
                "//score/config_management/config_daemon/code/services:internal_config_provider_reactor_mock",
            ],
        ),
    ]
]

cc_test(
    name = "unit_test",
    srcs = ["internal_config_provider_service_reactor_test.cpp"],
    features = COMPILER_WARNING_FEATURES,
    tags = [
        "unit",
    ],
    visibility = [
        "//score/config_management/config_daemon/code/services:__pkg__",
    ],
    deps = [
        "//score/config_management/config_daemon/code/data_model:parameterset_collection_mock",
        "//score/config_management/config_daemon/code/data_model/error",
        "//score/config_management/config_daemon/code/services/details:for_unit_test",
        "@score_logging//score/mw/log/test/console_logging_environment",
    ],
)
