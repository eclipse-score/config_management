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

COMMON_FEATURES = [
    "treat_warnings_as_errors",
    "strict_warnings",
    "additional_warnings",
]

cc_library(
    name = "error",
    srcs = ["parameter_set_storage_error.cpp"],
    hdrs = ["parameter_set_storage_error.h"],
    features = COMMON_FEATURES,
    tags = ["FUSA"],
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        "@score_baselibs//score/language/futurecpp",
        "@score_baselibs//score/result",
    ],
)

cc_test(
    name = "unit_test",
    srcs = ["parameter_set_storage_error_test.cpp"],
    features = COMMON_FEATURES,
    tags = ["unit"],
    visibility = ["//score/config_management/config_daemon/code/data_model/parameter_set_storage:__pkg__"],
    deps = [
        ":error",
        "@googletest//:gtest_main",
    ],
)
