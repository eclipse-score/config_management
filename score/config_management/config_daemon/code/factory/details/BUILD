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
        srcs = srcs,
        hdrs = [
            "factory_impl.h",
        ],
        features = COMPILER_WARNING_FEATURES,
        tags = ["FFI"],
        visibility = visibility,
        deps = [
            "//score/config_management/config_daemon/code/data_model/details:parameterset_collection_impl",
            "//score/config_management/config_daemon/code/data_model/details:parameterset_collection_manager_impl",
            "//score/config_management/config_daemon/code/json_helper/details",
            "//score/config_management/config_daemon/code/services/details:details_impl",
            "@score_baselibs//score/filesystem",
            "@score_baselibs//score/json:json_impl",
            "@score_communication//score/mw/service:factory",
        ] + dependencies,
    )
    for name, srcs, testonly, visibility, dependencies in [
        
        (
            "mw_factory",
            ["factory_mw_impl.cpp"],
            False,
            [
                "//score/config_management/config_daemon/code:__subpackages__",
            ],
            [
                "//score/config_management/config_daemon/code/factory:interface",
                "//score/config_management/config_daemon/code/plugins/plugin_collector/details:details",
                "//score/config_management/config_daemon/code/services/details/mw_com:details_mw_com_impl",
                "@score_communication//score/mw/service/backend/mw_com:provided_service_builder",
                "@score_communication//score/mw/service/backend/mw_com:provided_service_decorator",
                "//score/config_management/config_daemon/code/fault_event_reporter/details:details_score_impl",
                "//score/config_management/config_daemon/code/data_model/parameter_set_storage/details:details_score",
            ],
        ),
        
        (
            "mw_factory_for_unit_test",
            ["factory_mw_impl.cpp"],
            True,
            [
                "//score/config_management/config_daemon/code:__subpackages__",
            ],
            [
                "//score/config_management/config_daemon/code/factory:interface_for_unit_test",
                "//score/config_management/config_daemon/code/plugins/plugin_collector/details:details_for_unit_test",
                "//score/config_management/config_daemon/code/services/details/mw_com:details_mw_com_test",
                "@score_communication//score/mw/service/backend/mw_com:provided_service_builder",
                "//score/config_management/config_daemon/code/fault_event_reporter/details:details_score_impl",
                "@score_communication//score/mw/service/backend/mw_com:provided_service_decorator",
                "//score/config_management/config_daemon/code/data_model/parameter_set_storage/details:details_score",
            ],
        ),
    ]
]

[
    cc_test(
        name = name,
        testonly = True,
        srcs = [src],
        data = data,
        features = COMPILER_WARNING_FEATURES,
        tags = [
            "unit",
        ] + tag,
        visibility = [
            "//score/config_management/config_daemon/code/factory:__pkg__",
        ],
        deps = [
            dep,
            "//score/config_management/config_daemon/code/data_model:parameterset_collection_mock",
            "//score/config_management/config_daemon/code/plugins/plugin_collector:mock",
            "//score/config_management/config_daemon/code/services:mock",
            "@googletest//:gtest",
            "@googletest//:gtest_main",
            "@score_baselibs//score/language/futurecpp",
        ],
    )
    for name, src, dep, tag, data in [
        (
            "unit_test_mw_com",
            "factory_mw_impl_test.cpp",
            ":mw_factory_for_unit_test",
            [
                "mw_com",
                "exclusive",  # Sandboxing is not properly working with LoLa message passing 2.0 (Ticket-217341)
            ],
            ["//score/config_management/config_daemon/code/services/details/mw_com:mw_com_config"],
        ),
        
    ]
]
