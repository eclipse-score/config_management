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

load("@rules_cc//cc:defs.bzl", "cc_library")
load("@score_baselibs//:bazel/unit_tests.bzl", "cc_unit_test_suites_for_host_and_qnx")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

cc_library(
    name = "parameterset_collection",
    srcs = ["parameterset_collection.cpp"],
    hdrs = ["parameterset_collection.h"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FUSA"],
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        "//score/config_management/config_daemon/code/data_model:parameter_set_qualifier",
        "//score/config_management/config_daemon/code/data_model/parameterset_collection_interfaces:read_only_parameterset_collection",
        "@score_baselibs//score/json",
        "@score_baselibs//score/result",
    ],
)

cc_library(
    name = "parameterset_collection_mock",
    testonly = True,
    srcs = ["parameterset_collection_mock.cpp"],
    hdrs = ["parameterset_collection_mock.h"],
    features = COMPILER_WARNING_FEATURES,
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        ":parameterset_collection",
        "@googletest//:gtest",
    ],
)

cc_library(
    name = "parameterset_collection_manager",
    srcs = ["parameterset_collection_manager.cpp"],
    hdrs = ["parameterset_collection_manager.h"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FUSA"],
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        ":parameterset_collection",
        "//score/config_management/config_daemon/code/types/initial_qualifier_state",
        "@score_baselibs//score/result",
    ],
)

cc_library(
    name = "parameterset_collection_manager_mock",
    testonly = True,
    srcs = ["parameterset_collection_manager_mock.cpp"],
    hdrs = ["parameterset_collection_manager_mock.h"],
    features = COMPILER_WARNING_FEATURES,
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
        "//score:__subpackages__",
    ],
    deps = [
        ":parameterset_collection_manager",
        "@googletest//:gtest",
    ],
)

cc_library(
    name = "parameter_set_qualifier",
    hdrs = ["parameter_set_qualifier.h"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FUSA"],
    visibility = [
        "//score/config_management/config_daemon:__subpackages__",
        "//score/config_management/config_provider:__subpackages__",
    ],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [
        "//score/config_management/config_daemon/code/data_model/details:unit_test",
        "//score/config_management/config_daemon/code/data_model/error:unit_test",
    ],
    visibility = ["//score/config_management/config_daemon:__subpackages__"],
)
