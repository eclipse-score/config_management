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
load("@score_baselibs//:bazel/unit_tests.bzl", "cc_gtest_unit_test")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

[
    cc_library(
        name = name,
        testonly = testonly,
        srcs = srcs,
        hdrs = [
            "service_factory_impl.h",
        ],
        features = COMPILER_WARNING_FEATURES,
        tags = ["FFI"],
        visibility = visibility,
        deps = [
            "//score/config_management/config_daemon/code/factory:interface",
            "//score/config_management/config_daemon/code/services/details:details_impl",
            "@score_baselibs//score/filesystem",
            "@score_communication//score/mw/service:factory",
        ] + dependencies,
    )
    for name, srcs, testonly, visibility, dependencies in [
        (
            "factory_mw_com",
            ["factory_mw_com_impl.cpp"],
            False,
            [
                "//score/config_management/config_daemon/code:__subpackages__",
            ],
            [
                "//score/config_management/config_daemon/code/services/details/mw_com:details_mw_com_impl",
            ],
        ),
        (
            "factory_mw_com_for_unit_test",
            ["factory_mw_com_impl.cpp"],
            True,
            [
                "//score/config_management/config_daemon/code:__subpackages__",
            ],
            [
                "//score/config_management/config_daemon/code/factory:interface_for_unit_test",
                "//score/config_management/config_daemon/code/services/details/mw_com:details_mw_com_test",
            ],
        ),
    ]
]

[
    cc_library(
        name = name,
        testonly = testonly,
        srcs = srcs,
        hdrs = [
            "infrastructure_factory_impl.h",
        ],
        features = COMPILER_WARNING_FEATURES,
        tags = ["FFI"],
        visibility = [
            "//score/config_management/config_daemon/code:__subpackages__",
        ],
        deps = [
            "//score/config_management/config_daemon/code/data_model/details:parameterset_collection_impl",
            "//score/config_management/config_daemon/code/data_model/details:parameterset_collection_manager_impl",
            "//score/config_management/config_daemon/code/factory:interface",
            "//score/config_management/config_daemon/code/json_helper/details",
        ] + dependencies,
    )
    for name, srcs, testonly, dependencies in [
        (
            "infrastructure_factory_score",
            ["infrastructure_factory_score_impl.cpp"],
            False,
            [
                "//score/config_management/config_daemon/code/fault_event_reporter/details:details_score_impl",
                "//score/config_management/config_daemon/code/data_model/parameter_set_storage/details:details_score",
            ],
        ),
    ]
]

cc_library(
    name = "service_factory",
    deps = [":factory_mw_com"],
)

cc_library(
    name = "infrastructure_factory",
    deps = [":infrastructure_factory_score"],
)

# testonly counterparts, used by main_function_test to build the full FactoryImpl composition root
# against test-oriented (fake-backed) collaborators instead of the production ones.
cc_library(
    name = "service_factory_for_unit_test",
    testonly = True,
    deps = [":factory_mw_com_for_unit_test"],
)

cc_library(
    name = "infrastructure_factory_for_unit_test",
    testonly = True,
    deps = [":infrastructure_factory_score"],
)

cc_library(
    name = "factory_impl",
    srcs = ["factory_impl.cpp"],
    hdrs = ["factory_impl.h"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FFI"],
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        ":infrastructure_factory",
        ":service_factory",
        "//score/config_management/config_daemon/code/factory:interface",
        "//score/config_management/config_daemon/code/plugins/plugin_collector/details",
    ],
)

cc_library(
    name = "factory_impl_for_unit_test",
    testonly = True,
    srcs = ["factory_impl.cpp"],
    hdrs = ["factory_impl.h"],
    features = COMPILER_WARNING_FEATURES,
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        ":infrastructure_factory_for_unit_test",
        ":service_factory_for_unit_test",
        "//score/config_management/config_daemon/code/factory:interface_for_unit_test",
        "//score/config_management/config_daemon/code/plugins/plugin_collector/details:details_for_unit_test",
    ],
)

cc_gtest_unit_test(
    name = "unit_test_factory_impl",
    testonly = True,
    srcs = ["factory_impl_test.cpp"],
    features = COMPILER_WARNING_FEATURES,
    visibility = [
        "//score/config_management/config_daemon/code/factory:__pkg__",
    ],
    deps = [
        ":factory_impl_for_unit_test",
        "@score_baselibs//score/language/futurecpp",
    ],
)

[
    cc_gtest_unit_test(
        name = name,
        testonly = True,
        srcs = [src],
        data = data,
        features = COMPILER_WARNING_FEATURES,
        tags = tag,
        visibility = [
            "//score/config_management/config_daemon/code/factory:__pkg__",
        ],
        deps = [
            "//score/config_management/config_daemon/code/data_model:parameterset_collection_mock",
            "//score/config_management/config_daemon/code/plugins/plugin_collector:mock",
            "//score/config_management/config_daemon/code/services:mock",
            "@rules_cc//cc/runfiles",
            "@score_baselibs//score/language/futurecpp",
        ] + deps,
    )
    for name, src, deps, tag, data in [
        (
            "unit_test_mw_com",
            "factory_mw_com_impl_test.cpp",
            [
                ":factory_mw_com_for_unit_test",
                "//score/config_management/config_daemon/code/data_model/details:parameterset_collection_impl",
            ],
            [
                "mw_com",
                "exclusive",  # Sandboxing is not properly working with LoLa message passing 2.0 (Ticket-217341)
            ],
            ["//score/config_management/config_daemon/config:mw_com_config"],
        ),
    ]
]

[
    cc_gtest_unit_test(
        name = name,
        testonly = True,
        srcs = [src],
        features = COMPILER_WARNING_FEATURES,
        tags = tag,
        visibility = [
            "//score/config_management/config_daemon/code/factory:__pkg__",
        ],
        deps = [
            dep,
            "//score/config_management/config_daemon/code/data_model:parameterset_collection_mock",
            "@score_baselibs//score/language/futurecpp",
        ],
    )
    for name, src, dep, tag in [
        (
            "unit_test_infrastructure_factory_score",
            "infrastructure_factory_score_impl_test.cpp",
            ":infrastructure_factory_score",
            ["mw_com"],
        ),
    ]
]
