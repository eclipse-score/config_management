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

load("@bazel_skylib//rules:common_settings.bzl", "bool_flag")
load("@score_baselibs//:bazel/unit_tests.bzl", "cc_unit_test_suites_for_host_and_qnx")

bool_flag(
    name = "score_variant",
    build_setting_default = False,  # default is off, release variant used.
)

config_setting(
    name = "is_score_variant",
    flag_values = {":score_variant": "true"},
    visibility = [
        "@score_config_management//score/config_management/config_daemon:__subpackages__",
    ],
)

# Variables
COMMON_FEATURES = [
    "treat_warnings_as_errors",
    "strict_warnings",
    "additional_warnings",
]



cc_test(
    name = "main_function_test",
    testonly = True,
    srcs = [
        "main.cpp",
        "main_test.cpp",
    ],
    features = COMMON_FEATURES,
    tags = ["unit"],
    deps = [
        "@score_lifecycle_health//src/lifecycle_client_lib:applicationcontext_mock",
        "@score_lifecycle_health//src/lifecycle_client_lib:lifecycle_mock",
        "@score_config_management//score/config_management/config_daemon/code/app/details:app_for_unit_test",
    ] + select({
        ":is_score_variant": ["@score_config_management//score/config_management/config_daemon/code/factory/details:stub_factory_for_unit_test"],
        "//conditions:default": ["@score_config_management//score/config_management/config_daemon/code/factory/details:ara_factory_for_unit_test"],
    }),
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [
        ":main_function_test",
    ],
    test_suites_from_sub_packages = [
        "@score_config_management//score/config_management/config_daemon/code/app:unit_tests",
        "@score_config_management//score/config_management/config_daemon/code/factory:unit_tests",
        "@score_config_management//score/config_management/config_daemon/code/fault_event_reporter:unit_tests",
        "@score_config_management//score/config_management/config_daemon/code/data_model:unit_tests",
        "@score_config_management//score/config_management/config_daemon/code/plugins:unit_tests",
        "@score_config_management//score/config_management/config_daemon/code/services:unit_tests",
        "@score_config_management//score/config_management/config_daemon/code/proxies:unit_tests",
    ],
    visibility = ["@score_config_management//score/config_management/config_daemon:__subpackages__"],
)
