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
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

cc_library(
    name = "read_only_parameterset_collection",
    srcs = [
        "read_only_parameterset_collection.cpp",
    ],
    hdrs = [
        "read_only_parameterset_collection.h",
    ],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FFI"],
    visibility = ["//score/config_management/config_daemon:__subpackages__"],
    deps = [
        "@score_baselibs//score/json",
        "@score_baselibs//score/result",
        "@score_baselibs//score/language/futurecpp",
    ],
)

cc_library(
    name = "read_only_parameterset_collection_mock",
    testonly = True,
    srcs = [
        "read_only_parameterset_collection_mock.cpp",
    ],
    hdrs = [
        "read_only_parameterset_collection_mock.h",
    ],
    features = COMPILER_WARNING_FEATURES,
    deps = [
        ":read_only_parameterset_collection",
        "@googletest//:gtest",
    ],
)
