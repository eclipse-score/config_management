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
    name = "error",
    srcs = ["error.cpp"],
    hdrs = ["error.h"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FFI"],
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        "@score_baselibs//score/result",
    ],
)

cc_test(
    name = "unit_test",
    srcs = ["error_test.cpp"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["unit"],
    visibility = ["//score/config_management/config_daemon/code/data_model:__pkg__"],
    deps = [
        ":error",
        "@googletest//:gtest_main",
    ],
)
