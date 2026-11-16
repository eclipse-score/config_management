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
load("@score_baselibs//:bazel/unit_tests.bzl", "cc_gtest_unit_test")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

cc_library(
    name = "runtime_sized_array",
    srcs = ["runtime_sized_array.cpp"],
    hdrs = ["runtime_sized_array.h"],
    features = COMPILER_WARNING_FEATURES,
    deps = [
        "@score_baselibs//score/language/futurecpp",
    ],
)

cc_gtest_unit_test(
    name = "runtime_sized_array_test",
    srcs = ["runtime_sized_array_test.cpp"],
    deps = [
        ":runtime_sized_array",
    ],
)

cc_library(
    name = "internal_config_provider_type",
    srcs = [
        "internal_config_provider_type.cpp",
    ],
    hdrs = [
        "internal_config_provider_type.h",
    ],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FUSA"],
    visibility = [
        "//score/config_management/config_daemon:__subpackages__",
        "//score/config_management/config_provider:__subpackages__",
    ],
    deps = [
        ":runtime_sized_array",
        "@score_communication//score/memory/shared:polymorphic_offset_ptr_allocator",
        "@score_communication//score/mw/com",
    ],
)
