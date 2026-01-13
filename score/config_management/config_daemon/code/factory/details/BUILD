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

[
    cc_library(
        name = name,
        testonly = testonly,
        srcs = srcs,
        hdrs = [
            "factory_impl.h",
        ],
        features = [
            "treat_warnings_as_errors",
            "additional_warnings",
            "strict_warnings",
        ],
        tags = ["FFI"],
        visibility = visibility,
        deps = [
            "@score_baselibs//score/filesystem",
            "@score_baselibs//score/hash:safe_hash",
            "@score_baselibs//score/json:json_impl",
            "@score_communication//score/mw/service:factory",
            "@score_config_management//score/config_management/config_daemon/code/data_model/details:parameterset_collection_impl",
            "@score_config_management//score/config_management/config_daemon/code/factory:interface",
            "@score_config_management//score/config_management/config_daemon/code/json_helper/details",
        ] + dependencies,
    )
    for name, srcs, testonly, visibility, dependencies in [
        
        (
            "mw_factory",
            ["factory_mw_impl.cpp"],
            False,
            [
                "@score_config_management//score/config_management/config_daemon/code:__subpackages__",
            ],
            [
                "@score_config_management//score/config_management/config_daemon/code/plugins/plugin_collector/details:details",
                "@score_config_management//score/config_management/config_daemon/code/services/details:mw_impl",
                "@score_communication//score/mw/service/backend/mw_com:provided_service_builder",
                "@score_communication//score/mw/service/backend/mw_com:provided_service_decorator",
                "@score_config_management//score/config_management/config_daemon/code/fault_event_reporter/details:details_score_impl",
            ],
        ),
        (
            "stub_factory",
            ["factory_stub_impl.cpp"],
            False,
            [
                "@score_config_management//score/config_management/config_daemon/code:__subpackages__",
            ],
            [
            ],
        ),
        
        (
            "mw_factory_for_unit_test",
            ["factory_mw_impl.cpp"],
            True,
            [
                "@score_config_management//score/config_management/config_daemon/code:__subpackages__",
            ],
            [
                "@score_config_management//score/config_management/config_daemon/code/plugins/plugin_collector/details:details_for_unit_test",
                "@score_config_management//score/config_management/config_daemon/code/services/details:for_mw_unit_test",
                "@score_baselibs//score/hash:hash_mock",
                "@score_communication//score/mw/service/backend/mw_com:provided_service_builder",
                "@score_config_management//score/config_management/config_daemon/code/fault_event_reporter/details:details_score_impl",
                "@score_communication//score/mw/service/backend/mw_com:provided_service_decorator",
            ],
        ),
        (
            "stub_factory_for_unit_test",
            ["factory_stub_impl.cpp"],
            True,
            [
                "@score_config_management//score/config_management/config_daemon/code:__subpackages__",
            ],
            [
            ],
        ),
    ]
]

filegroup(
    name = "test_mw_com_config",
    srcs = ["mw_com_config.json"],
)

[
    cc_test(
        name = name,
        testonly = True,
        srcs = [src],
        data = data,
        features = [
            "treat_warnings_as_errors",
            "additional_warnings",
            "strict_warnings",
        ],
        tags = [
            "unit",
        ] + tag,
        target_compatible_with = select({
            "@score_config_management//score/config_management/config_daemon/code:is_score_variant": ["@platforms//:incompatible"],
            "//conditions:default": [],
        }),
        visibility = [
            "@score_config_management//score/config_management/config_daemon/code/factory:__pkg__",
        ],
        deps = [
            dep,
            "@score_config_management//score/config_management/config_daemon/code/data_model:parameterset_collection_mock",
            "@score_config_management//score/config_management/config_daemon/code/plugins/plugin_collector:mock",
            "@score_config_management//score/config_management/config_daemon/code/services:mock",
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
            [":test_mw_com_config"],
        ),
        
    ]
]
