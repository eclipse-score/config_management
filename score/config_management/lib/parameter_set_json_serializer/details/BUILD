# *******************************************************************************
# Copyright (c) 2026 Contributors to the Eclipse Foundation
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
load("@score_baselibs//:bazel/unit_tests.bzl", "cc_gtest_unit_test")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

cc_library(
    name = "parameter_set_json_serializer_impl",
    srcs = ["parameter_set_json_serializer_impl.cpp"],
    hdrs = ["parameter_set_json_serializer_impl.h"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FUSA"],
    visibility = [
        "//score/config_management/config_daemon:__subpackages__",
    ],
    deps = [
        "//score/config_management/lib/parameter_set_json_serializer",
        "//score/config_management/lib/parameter_set_json_serializer/error",
        "@score_baselibs//score/json",
        "@score_baselibs//score/language/futurecpp",
    ],
)

cc_gtest_unit_test(
    name = "parameter_set_json_serializer_impl_test",
    srcs = ["parameter_set_json_serializer_impl_test.cpp"],
    deps = [
        ":parameter_set_json_serializer_impl",
        "//score/config_management/lib/parameter_set_json_serializer/error",
        "@score_baselibs//score/json",
    ],
)
