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
load("@rules_cc//cc:defs.bzl", "cc_test")
load("@score_baselibs//:bazel/unit_tests.bzl", "cc_unit_test_suites_for_host_and_qnx")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")
load(":custom.bzl", "load_custom_targets", "load_custom_test_suites")

bool_flag(
    name = "score_variant",
    build_setting_default = False,  # default is off, release variant used.
)

config_setting(
    name = "is_score_variant",
    flag_values = {":score_variant": "true"},
    visibility = [
        "//score/config_management/config_daemon:__subpackages__",
    ],
)

cc_test(
    name = "main_function_test",
    testonly = True,
    srcs = [
        "main.cpp",
        "main_test.cpp",
    ],
    features = COMPILER_WARNING_FEATURES,
    tags = ["unit"],
    deps = [
        "//score/config_management/config_daemon/code/app/details:app_for_unit_test",
        "@score_lifecycle_health//score/launch_manager/src/lifecycle_client:applicationcontext_mock",
        "@score_lifecycle_health//score/launch_manager/src/lifecycle_client:lifecycle_mock",
        "@score_lifecycle_health//score/launch_manager/src/lifecycle_client:runapplication",
    ] + select({
        ":is_score_variant": ["//score/config_management/config_daemon/code/factory/details:mw_factory_for_unit_test"],
        "//conditions:default": ["//score/config_management/config_daemon/code/factory/details:ara_factory_for_unit_test"],
    }),
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [
        ":main_function_test",
    ],
    test_suites_from_sub_packages = [
        "//score/config_management/config_daemon/code/app:unit_tests",
        "//score/config_management/config_daemon/code/factory:unit_tests",
        "//score/config_management/config_daemon/code/fault_event_reporter:unit_tests",
        "//score/config_management/config_daemon/code/data_model:unit_tests",
        "//score/config_management/config_daemon/code/data_model/parameter_set_storage:unit_tests",
        "//score/config_management/config_daemon/code/services:unit_tests",
        "//score/config_management/config_daemon/code/plugins:unit_tests",
    ] + load_custom_test_suites(),
    visibility = ["//score/config_management/config_daemon:__subpackages__"],
)

load_custom_targets()
