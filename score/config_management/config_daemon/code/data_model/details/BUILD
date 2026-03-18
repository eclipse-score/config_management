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

cc_library(
    name = "parameterset_collection_impl",
    srcs = [
        "common.cpp",
        "parameter_set_impl.cpp",
        "parameterset_collection_impl.cpp",
    ],
    hdrs = [
        "common.h",
        "parameter_impl.h",
        "parameter_set_impl.h",
        "parameterset_collection_impl.h",
    ],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FUSA"],
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
        "//score:__subpackages__",
    ],
    deps = [
        "@score_baselibs//score/filesystem",
        "@score_baselibs//score/json",
        "@score_logging//score/mw/log",
        "//score/config_management/config_daemon/code/data_model:parameter_set_qualifier",
        "//score/config_management/config_daemon/code/data_model:parameterset_collection",
        "//score/config_management/config_daemon/code/data_model/error",
        "//score/config_management/config_daemon/code/data_model/parameter_set_storage",
        "@score_baselibs//score/language/futurecpp",
    ],
)

cc_library(
    name = "parameterset_collection_manager_impl",
    srcs = ["parameterset_collection_manager_impl.cpp"],
    hdrs = ["parameterset_collection_manager_impl.h"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FUSA"],
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        ":parameterset_collection_impl",
        "@score_logging//score/mw/log",
        "//score/config_management/config_daemon/code/data_model:parameterset_collection_manager",
        "//score/config_management/config_daemon/code/data_model/error",
        "//score/config_management/config_daemon/code/data_model/parameter_set_storage",
        "//score/config_management/config_daemon/code/plugins:plugin",
    ],
)

cc_test(
    name = "unit_test",
    srcs = [
        "parameter_set_impl_test.cpp",
        "parameterset_collection_impl_test.cpp",
    ],
    features = COMPILER_WARNING_FEATURES,
    tags = ["unit"],
    visibility = ["//score/config_management/config_daemon/code/data_model:__pkg__"],
    deps = [
        ":parameterset_collection_impl",
        "@score_baselibs//score/json:mock",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "unit_test_manager",
    srcs = ["parameterset_collection_manager_impl_test.cpp"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["unit"],
    visibility = ["//score/config_management/config_daemon/code/data_model:__pkg__"],
    deps = [
        ":parameterset_collection_manager_impl",
        "@score_logging//score/mw/log/test/console_logging_environment",
        "//score/config_management/config_daemon/code/data_model/parameter_set_storage:mock",
        "//score/config_management/config_daemon/code/plugins:mock",
        "@googletest//:gtest_main",
    ],
)
