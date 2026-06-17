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
load(":custom.bzl", "load_custom_targets")

COMMON_FEATURES = [
    "treat_warnings_as_errors",
    "strict_warnings",
    "additional_warnings",
]

[
    cc_library(
        name = name,
        testonly = testonly,
        srcs = [
            "parameter_set_storage_score_impl.cpp",
        ],
        hdrs = [
            "parameter_set_storage_score_impl.h",
        ],
        features = COMMON_FEATURES,
        tags = ["FUSA"],
        visibility = [
            "//score/config_management/config_daemon/code:__subpackages__",
        ],
        deps = [
            "//score/config_management/config_daemon/code/data_model:parameterset_collection",
            "//score/config_management/config_daemon/code/data_model/parameter_set_storage",
            "//score/config_management/config_daemon/code/data_model/parameter_set_storage/error",
            "@score_baselibs//score/hash:safe_hash",
            "@score_baselibs//score/json",
        ] + dependencies,
    )
    for name, testonly, dependencies in [
        (
            "details_score",
            False,
            [
                "@score_persistency//:kvs_cpp",
            ],
        ),
        (
            "details_score_for_unit_test",
            True,
            [
                "//score/config_management/config_daemon/code/data_model/parameter_set_storage/details/score_kvs_stub:score_kvs_mock",
            ],
        ),
    ]
]

cc_test(
    name = "unit_test_score",
    srcs = ["parameter_set_storage_score_impl_test.cpp"],
    features = COMMON_FEATURES,
    tags = ["unit"],
    visibility = [
        "//score/config_management/config_daemon/code/data_model/parameter_set_storage:__pkg__",
    ],
    deps = [
        ":details_score_for_unit_test",
        "//score/config_management/config_daemon/code/data_model:parameterset_collection_mock",
        "@score_logging//score/mw/log/test/console_logging_environment",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

load_custom_targets()

cc_test(
    name = "unit_test",
    srcs = select({
        "//score/config_management/config_daemon/code:is_score_variant": ["parameter_set_storage_score_impl_test.cpp"],
        "//conditions:default": ["parameter_set_storage_impl_test.cpp"],
    }),
    features = COMMON_FEATURES,
    tags = ["unit"],
    visibility = [
        "//score/config_management/config_daemon/code/data_model/parameter_set_storage:__pkg__",
    ],
    deps = [
        "//score/config_management/config_daemon/code/data_model:parameterset_collection_mock",
        "@score_logging//score/mw/log/test/console_logging_environment",
        "@googletest//:gtest",
    ] + select({
        "//score/config_management/config_daemon/code:is_score_variant": [
            ":details_score_for_unit_test",
            "@googletest//:gtest_main",
        ],
        "//conditions:default": [
            ":details_for_unit_test",
            "@score_baselibs//score/filesystem:mock",
            "@score_baselibs//score/hash:hash_mock",
            "@score_baselibs//score/json:mock",
        ],
    }),
)
