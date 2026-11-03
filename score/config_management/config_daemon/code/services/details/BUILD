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

[
    cc_library(
        name = "internal_config_provider_service" + name,
        testonly = test_only,
        srcs = [
            "internal_config_provider_service_impl.cpp",
        ],
        hdrs = [
            "internal_config_provider_service_impl.h",
        ],
        features = COMPILER_WARNING_FEATURES,
        tags = ["FUSA"],
        visibility = ["//score/config_management/config_daemon/code:__subpackages__"],
        deps = [
            "//score/config_management/config_daemon/code/data_model/error",
            "//score/config_management/config_daemon/code/services",
            "//score/config_management/lib/mw_com_types:internal_config_provider_type",
            "@score_logging//score/mw/log",
        ] + dep,
    )
    for name, dep, test_only in [
        (
            "_impl",
            [
                "@score_baselibs//score/result",
                "@score_communication//score/mw/com",
                "//score/config_management/config_daemon/code/services:internal_config_provider_reactor",
                "//score/config_management/config_daemon/code/data_model/parameterset_collection_interfaces:read_only_parameterset_collection",
            ],
            False,
        ),
        (
            "_for_unit_test",
            [
                "//score/config_management/config_daemon/code/services:internal_config_provider_reactor_mock",
                "//score/config_management/config_daemon/code/data_model/parameterset_collection_interfaces:read_only_parameterset_collection",
            ],
            True,
        ),
    ]
]

genrule(
    name = "mw_com_config_json_header",
    testonly = True,
    srcs = ["//score/config_management/config_daemon/config:mw_com_config"],
    outs = ["mw_com_config_json.h"],
    cmd = """G=$$(printf %s "$@" | sed 's#^.*/bin/##' | tr -c 'A-Za-z0-9' '_' | tr 'a-z' 'A-Z')
{
    echo "#ifndef $$G"
    echo "#define $$G"
    echo 'constexpr char kMwComConfigJson[] = R"JSON('
    cat $(SRCS)
    echo ')JSON";'
    echo "#endif  // $$G"
} > $@""",
)

cc_library(
    name = "mw_com_config_json",
    testonly = True,
    hdrs = [":mw_com_config_json_header"],
    visibility = ["//score/config_management/config_daemon/code/factory/details:__pkg__"],
)

cc_test(
    name = "unit_test_internal_config_provider_service_impl",
    srcs = [
        "internal_config_provider_service_impl_test.cpp",
    ],
    features = COMPILER_WARNING_FEATURES + [
        "aborts_upon_exception",
    ],
    tags = [
        "exclusive",  # Sandboxing is not properly working with LoLa message passing 2.0 (Ticket-217341)
        "mw_com",
        "unit",
    ],
    visibility = ["//score/config_management/config_daemon/code/services/details:__pkg__"],
    deps = [
        ":internal_config_provider_service_for_unit_test",
        ":mw_com_config_json",
        "@googletest//:gtest_main",
    ],
)
