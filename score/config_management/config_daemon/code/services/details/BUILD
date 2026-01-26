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

COMMON_FEATURES = [
    "treat_warnings_as_errors",
    "strict_warnings",
    "additional_warnings",
]

[
    cc_library(
        name = name,
        testonly = testonly,
        srcs = srcs,
        hdrs = hdrs,
        features = COMMON_FEATURES,
        tags = ["FUSA"],
        visibility = [
            "@score-config_management//score/config_management/config_daemon/code:__subpackages__",
        ],
        deps = dependencies,
    )
    for name, srcs, hdrs, testonly, dependencies in [
        (
            "mw_impl",
            [
                "internal_config_provider_service_reactor_impl.cpp",
                "mw_com/internal_config_provider_service_impl.cpp",
            ],
            [
                "internal_config_provider_service_reactor_impl.h",
                "mw_com/internal_config_provider_service_impl.h",
            ],
            False,
            [
                "@score-config_management//score/config_management/config_daemon/code/services",
                "@score-baselibs//score/result",
                "@score_communication//score/mw/com",
                "@score-config_management//score/config_management/config_daemon/code/services/details/mw_com/generated_service:internal_config_provider_type",
                "@score-config_management//score/config_management/config_daemon/code/services:internal_config_provider_reactor",
                "@score-config_management//score/config_management/config_daemon/code/data_model/parameterset_collection_interfaces:read_only_parameterset_collection",
                "@score-baselibs//score/mw/log",
            ],
        ),
        (
            "for_mw_unit_test",
            [
                "internal_config_provider_service_reactor_impl.cpp",
                "mw_com/internal_config_provider_service_impl.cpp",
            ],
            [
                "internal_config_provider_service_reactor_impl.h",
                "mw_com/internal_config_provider_service_impl.h",
            ],
            True,
            [
                "@score-config_management//score/config_management/config_daemon/code/services:internal_config_provider_reactor_mock",
                "@score-config_management//score/config_management/config_daemon/code:config_daemon_mock_bindings",
                "@score-config_management//score/config_management/config_daemon/code/services",
                "//platform/aas/sysfunc/common/ConfigProvider/code/parameter_set",
                "@score-config_management//score/config_management/config_daemon/code/services/details/mw_com/generated_service:internal_config_provider_type",
                "@score-config_management//score/config_management/config_daemon/code/data_model/parameterset_collection_interfaces:read_only_parameterset_collection",
            ],
        ),
    ]
]

filegroup(
    name = "test_mw_com_config",
    srcs = ["mw_com/mw_com_config.json"],
)

common_srcs = [
    "internal_config_provider_service_reactor_test.cpp",
]

common_deps = [
    "@score-baselibs//score/mw/log/test/console_logging_environment",
    "@score-config_management//score/config_management/config_daemon/code/data_model:parameterset_collection_mock",
    "@score-config_management//score/config_management/config_daemon/code/data_model/error",
]

[
    cc_test(
        name = name,
        srcs = common_srcs + extra_srcs,
        data = data,
        features = COMMON_FEATURES,
        tags = [
            "unit",
        ] + tag,
        visibility = [
            "@score-config_management//score/config_management/config_daemon/code/services:__pkg__",
        ],
        deps = common_deps + extra_deps,
    )
    for name, tag, extra_srcs, data, extra_deps in [
        (
            "unit_tests_mw_com",
            [
                "mw_com",
                "exclusive",  # Sandboxing is not properly working with LoLa message passing 2.0 (Ticket-217341)
            ],
            [
                "mw_com/internal_config_provider_service_impl_test.cpp",
            ],
            [":test_mw_com_config"],
            ["@score-config_management//score/config_management/config_daemon/code/services/details:for_mw_unit_test"],
        ),
    ]
]
