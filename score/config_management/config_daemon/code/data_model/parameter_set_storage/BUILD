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

COMMON_FEATURES = [
    "treat_warnings_as_errors",
    "strict_warnings",
    "additional_warnings",
]

cc_library(
    name = "parameter_set_storage",
    srcs = ["parameter_set_storage.cpp"],
    hdrs = ["parameter_set_storage.h"],
    features = COMMON_FEATURES,
    tags = ["FUSA"],
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        "@score_baselibs//score/result",
    ],
)

cc_library(
    name = "mock",
    testonly = True,
    hdrs = ["parameter_set_storage_mock.h"],
    features = COMMON_FEATURES,
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        ":parameter_set_storage",
        "@googletest//:gtest",
    ],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [
        "//score/config_management/config_daemon/code/data_model/parameter_set_storage/error:unit_test",
        "//score/config_management/config_daemon/code/data_model/parameter_set_storage/details:unit_test_score",
    ],
    visibility = ["//score/config_management/config_daemon/code:__pkg__"],
)
