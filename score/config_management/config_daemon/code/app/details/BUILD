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
load("@score_tooling//bazel/rules/rules_score:rules_score.bzl", "unit")

cc_library(
    name = "app",
    testonly = False,
    srcs = ["config_daemon_impl.cpp"],
    hdrs = ["config_daemon_impl.h"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FUSA"],
    visibility = [
        "//score/config_management/config_daemon/code:__pkg__",
    ],
    deps = [
        "//score/config_management/config_daemon/code/app:interface",
        "//score/config_management/config_daemon/code/data_model:parameterset_collection_manager",
        "//score/config_management/config_daemon/code/data_model/details:parameterset_collection_manager_impl",
        "//score/config_management/config_daemon/code/factory:interface",
        "@score_baselibs//score/concurrency:interruptible_wait",
        "@score_baselibs//score/scope_exit",
        "@score_lifecycle_health//score/launch_manager/src/lifecycle_client:application",
        "@score_logging//score/mw/log",
    ],
)

cc_library(
    name = "app_for_unit_test",
    testonly = True,
    srcs = ["config_daemon_impl.cpp"],
    hdrs = ["config_daemon_impl.h"],
    features = COMPILER_WARNING_FEATURES,
    visibility = [
        "//score/config_management/config_daemon/code:__pkg__",
    ],
    deps = [
        "//score/config_management/config_daemon/code/app:interface",
        "//score/config_management/config_daemon/code/data_model:parameterset_collection_manager",
        "//score/config_management/config_daemon/code/data_model/details:parameterset_collection_manager_impl",
        "//score/config_management/config_daemon/code/factory:interface_for_unit_test",
        "//score/config_management/config_daemon/code/fault_event_reporter",
        "@score_baselibs//score/scope_exit",
        "@score_lifecycle_health//score/launch_manager/src/lifecycle_client:applicationcontext_mock",
        "@score_logging//score/mw/log",
    ],
)

cc_test(
    name = "unit_test",
    testonly = True,
    srcs = [
        "config_daemon_impl_test.cpp",
    ],
    features = COMPILER_WARNING_FEATURES,
    tags = ["unit"],
    visibility = [
        "//requirements:__pkg__",
        "//score/config_management/config_daemon/code/app:__pkg__",
        "//score/config_management/config_daemon/code/app/details:__pkg__",
    ],
    deps = [
        ":app_for_unit_test",
        "//score/config_management/config_daemon/code/data_model:parameterset_collection_manager_mock",
        "//score/config_management/config_daemon/code/factory:mock",
        "//score/config_management/config_daemon/code/fault_event_reporter:mock",
        "//score/config_management/config_daemon/code/plugins:mock",
        "//score/config_management/config_daemon/code/plugins/plugin_collector:mock",
        "//score/config_management/config_daemon/code/services:mock",
        "@googletest//:gtest_main",
        "@score_baselibs//score/os/mocklib:stat_mock",
        "@score_communication//score/mw/service:factory",
        "@score_communication//score/mw/service:provided_service_container",
        "@score_lifecycle_health//score/launch_manager/src/lifecycle_client:applicationcontext",
        "@score_lifecycle_health//score/launch_manager/src/lifecycle_client:lifecycle_mock",
    ],
)

unit(
    name = "config_daemon_app_unit",
    tests = [":unit_test"],
    unit_design = [],
    visibility = ["//score/config_management/dependability:__pkg__"],
    implementation = [":app"],
)
