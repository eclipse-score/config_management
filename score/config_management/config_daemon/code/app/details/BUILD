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

cc_library(
    name = "app",
    testonly = False,
    srcs = ["config_daemon_impl.cpp"],
    hdrs = ["config_daemon_impl.h"],
    features = COMMON_FEATURES,
    tags = ["FUSA"],
    visibility = [
        "@score-config_management//score/config_management/config_daemon/code:__pkg__",
    ],
    deps = [
        "@score-baselibs//score/utils:scoped_operation",
        "//platform/aas/mw/lifecycle:application",
        "@score-baselibs//score/mw/log",
        "@score-config_management//score/config_management/config_daemon/code/app:interface",
        "@score-config_management//score/config_management/config_daemon/code/data_model:parameterset_collection",
        "@score-config_management//score/config_management/config_daemon/code/factory:interface",
    ],
)

cc_library(
    name = "app_for_unit_test",
    testonly = True,
    srcs = ["config_daemon_impl.cpp"],
    hdrs = ["config_daemon_impl.h"],
    features = COMMON_FEATURES,
    visibility = [
        "@score-config_management//score/config_management/config_daemon/code:__pkg__",
    ],
    deps = [
        "@score-baselibs//score/utils:scoped_operation",
        "//platform/aas/mw/lifecycle:application_mock",
        "@score-config_management//score/config_management/config_daemon/code/app:interface",
        "@score-config_management//score/config_management/config_daemon/code/data_model:parameterset_collection",
        "@score-config_management//score/config_management/config_daemon/code/factory:interface",
        "@score-config_management//score/config_management/config_daemon/code/fault_event_reporter",
    ],
)

cc_test(
    name = "unit_test",
    testonly = True,
    srcs = [
        "config_daemon_impl_test.cpp",
    ],
    features = COMMON_FEATURES,
    tags = ["unit"],
    visibility = ["@score-config_management//score/config_management/config_daemon/code/app:__pkg__"],
    deps = [
        ":app_for_unit_test",
        "@score-baselibs//score/os/mocklib:stat_mock",
        "//platform/aas/mw/lifecycle:applicationcontext",
        "//platform/aas/mw/lifecycle:lifecycle_mock",
        "//platform/aas/mw/service:factory",
        "//platform/aas/mw/service/mw:mw_test",
        "@score-config_management//score/config_management/config_daemon/code/data_model:parameterset_collection_mock",
        "@score-config_management//score/config_management/config_daemon/code/factory:mock",
        "@score-config_management//score/config_management/config_daemon/code/fault_event_reporter:mock",
        "@score-config_management//score/config_management/config_daemon/code/plugins:mock",
        "@score-config_management//score/config_management/config_daemon/code/plugins/plugin_collector:mock",
        "@score-config_management//score/config_management/config_daemon/code/services:mock",
    ],
)
