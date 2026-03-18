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
    name = "json_helper",
    testonly = False,
    srcs = [],
    hdrs = [
        "json_helper.h",
    ],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FFI"],
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        "@score_baselibs//score/filesystem",
        "@score_baselibs//score/json",
    ],
)

cc_library(
    name = "mock",
    testonly = True,
    srcs = [],
    hdrs = [
        "json_helper_mock.h",
    ],
    features = COMPILER_WARNING_FEATURES,
    visibility = [
        "//score/config_management/config_daemon:__subpackages__",
    ],
    deps = [
        ":json_helper",
    ],
)
