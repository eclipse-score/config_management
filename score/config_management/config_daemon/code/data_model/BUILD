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

load("@score-baselibs//:bazel/unit_tests.bzl", "cc_unit_test_suites_for_host_and_qnx")

COMMON_FEATURES = [
    "treat_warnings_as_errors",
    "strict_warnings",
    "additional_warnings",
]

cc_library(
    name = "parameterset_collection",
    srcs = ["parameterset_collection.cpp"],
    hdrs = ["parameterset_collection.h"],
    features = COMMON_FEATURES,
    tags = ["FUSA"],
    visibility = [
        "@score-config_management//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        "@score-baselibs//score/json",
        "@score-baselibs//score/result",
        "@score-config_management//score/config_management/config_daemon/code/data_model:parameter_set_qualifier",
        "@score-config_management//score/config_management/config_daemon/code/data_model/parameterset_collection_interfaces:read_only_parameterset_collection",
    ],
)

cc_library(
    name = "parameterset_collection_mock",
    testonly = True,
    srcs = ["parameterset_collection_mock.cpp"],
    hdrs = ["parameterset_collection_mock.h"],
    features = COMMON_FEATURES,
    visibility = [
        "@score-config_management//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        ":parameterset_collection",
        "@googletest//:gtest",
    ],
)

cc_library(
    name = "parameter_set_qualifier",
    hdrs = ["parameter_set_qualifier.h"],
    features = COMMON_FEATURES,
    tags = ["FUSA"],
    visibility = [
        "//platform/aas/sysfunc:__subpackages__",
    ],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [
        "@score-config_management//score/config_management/config_daemon/code/data_model/details:unit_test",
        "@score-config_management//score/config_management/config_daemon/code/data_model/error:unit_test",
    ],
    visibility = ["@score-config_management//score/config_management/config_daemon:__subpackages__"],
)
