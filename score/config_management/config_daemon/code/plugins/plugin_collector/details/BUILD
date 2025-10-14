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
        srcs = ["plugin_collector_impl.cpp"],
        hdrs = [
            "plugin_collector_impl.h",
        ],
        features = [
            "treat_warnings_as_errors",
            "strict_warnings",
            "additional_warnings",
        ],
        tags = ["FUSA"],
        visibility = [
            "@score-config_management//score/config_management/config_daemon/code:__subpackages__",
        ],
        deps = [
            "@score-baselibs//score/mw/log",
            "@score-config_management//score/config_management/config_daemon/code/plugins:plugin",
            "@score-config_management//score/config_management/config_daemon/code/plugins/plugin_collector:interface",
        ] + dependencies,
    )
    for name, testonly, dependencies in [
        (
            "details",
            False,
            [
                "@score-config_management//score/config_management/config_daemon/code/plugins:plugin_creator",
            ],
        ),
        (
            "details_for_unit_test",
            True,
            [
                "@score-config_management//score/config_management/config_daemon/code/plugins:mock",
                "@score-config_management//score/config_management/config_daemon/code/plugins:plugin_creator_mock",
            ],
        ),
    ]
]

cc_test(
    name = "unit_test",
    srcs = ["plugin_collector_impl_test.cpp"],
    features = [
        "treat_warnings_as_errors",
        "strict_warnings",
        "additional_warnings",
    ],
    tags = ["unit"],
    visibility = ["@score-config_management//score/config_management/config_daemon:__subpackages__"],
    deps = [
        ":details_for_unit_test",
        "@score-baselibs//score/mw/log/test/console_logging_environment",
    ],
)
