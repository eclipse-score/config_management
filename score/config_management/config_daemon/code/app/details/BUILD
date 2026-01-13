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
        "@score_config_management//score/config_management/config_daemon/code:__pkg__",
    ],
    deps = [
        "@score_baselibs//score/utils:scoped_operation",
        "@score_lifecycle_health//src/lifecycle_client_lib:application",
        "@score_baselibs//score/mw/log",
        "@score_config_management//score/config_management/config_daemon/code/app:interface",
        "@score_config_management//score/config_management/config_daemon/code/data_model:parameterset_collection",
        "@score_config_management//score/config_management/config_daemon/code/factory:interface",
    ],
)

cc_library(
    name = "app_for_unit_test",
    testonly = True,
    srcs = ["config_daemon_impl.cpp"],
    hdrs = ["config_daemon_impl.h"],
    features = COMMON_FEATURES,
    visibility = [
        "@score_config_management//score/config_management/config_daemon/code:__pkg__",
    ],
    deps = [
        "@score_baselibs//score/utils:scoped_operation",
        "@score_lifecycle_health//src/lifecycle_client_lib:application_mock",
        "@score_baselibs//score/mw/log",
        "@score_config_management//score/config_management/config_daemon/code/app:interface",
        "@score_config_management//score/config_management/config_daemon/code/data_model:parameterset_collection",
        "@score_config_management//score/config_management/config_daemon/code/factory:interface",
        "@score_config_management//score/config_management/config_daemon/code/fault_event_reporter",
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
    visibility = ["@score_config_management//score/config_management/config_daemon/code/app:__pkg__"],
    deps = [
        ":app_for_unit_test",
        "@score_baselibs//score/os/mocklib:stat_mock",
        "@score_lifecycle_health//src/lifecycle_client_lib:applicationcontext",
        "@score_lifecycle_health//src/lifecycle_client_lib:lifecycle_mock",
        "@score_communication//score/mw/service:factory",
        "@score_communication//score/mw/service/mw:mw_test",
        "@score_config_management//score/config_management/config_daemon/code/data_model:parameterset_collection_mock",
        "@score_config_management//score/config_management/config_daemon/code/factory:mock",
        "@score_config_management//score/config_management/config_daemon/code/fault_event_reporter:mock",
        "@score_config_management//score/config_management/config_daemon/code/plugins:mock",
        "@score_config_management//score/config_management/config_daemon/code/plugins/plugin_collector:mock",
        "@score_config_management//score/config_management/config_daemon/code/services:mock",
    ],
)
