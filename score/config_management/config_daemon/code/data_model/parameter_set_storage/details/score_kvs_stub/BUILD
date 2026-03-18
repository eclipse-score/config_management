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

# Stub replacements for score-persistency headers (kvs.hpp / kvsbuilder.hpp / kvsvalue.hpp).
# Used when compiling score-variant source files (e.g. factory_mw_impl.cpp,
# parameter_set_storage_score_impl.cpp) under the SPP toolchain where the real
# score-baselibs / score-persistency headers would cause namespace clashes.
#
# The stubs expose exactly the same types and method signatures used by those files
# but have no real implementation — every operation is a no-op / returns failure.
# On the actual score build, the real @score-persistency//:kvs_cpp is used instead.
cc_library(
    name = "score_kvs_stub",
    hdrs = [
        "kvs.hpp",
        "kvsbuilder.hpp",
        "kvsvalue.hpp",
    ],
    # Expose the directory itself as a system include path so that
    # `#include "kvs.hpp"` resolves here, mirroring how score-persistency does it.
    includes = ["."],
    tags = ["FUSA"],
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        "@score_baselibs//score/result",
        "//score/config_management/config_daemon/code/data_model/parameter_set_storage/error",
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
