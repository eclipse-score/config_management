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

# Stub replacements for score-persistency headers (score/kvs/kvs.h / kvs_builder.h / kvs_value.h).
# Used when compiling score-variant source files (e.g. parameter_set_storage_score_impl.cpp)
# in builds where the real
# score-baselibs / score-persistency headers would cause namespace clashes.
#
# The stubs expose exactly the same types and method signatures used by those files
# but have no real implementation — every operation is a no-op / returns failure.
# On the actual score build, the real @score_persistency//score/kvs is used instead.
cc_library(
    name = "score_kvs_stub",
    hdrs = [
        "kvs.h",
        "kvs_builder.h",
        "kvs_value.h",
    ],
    # Mirror score-persistency's `#include "score/kvs/kvs.h"` include paths.
    include_prefix = "score/kvs",
    tags = ["FUSA"],
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        "//score/config_management/config_daemon/code/data_model/parameter_set_storage/error",
        "@score_baselibs//score/result",
    ],
)

cc_library(
    name = "score_kvs_mock",
    testonly = True,
    srcs = ["kvs_mock.cpp"],
    hdrs = ["kvs_mock.hpp"],
    includes = ["."],
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        ":score_kvs_stub",
        "@googletest//:gtest",
    ],
)
