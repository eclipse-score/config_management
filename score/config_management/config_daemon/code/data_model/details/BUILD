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

# Variables
COMMON_FEATURES = [
    "treat_warnings_as_errors",
    "strict_warnings",
    "additional_warnings",
]

cc_library(
    name = "parameterset_collection_impl",
    srcs = [
        "common.cpp",
        "parameter_set_impl.cpp",
        "parameterset_collection_impl.cpp",
    ],
    hdrs = [
        "common.h",
        "parameter_impl.h",
        "parameter_set_impl.h",
        "parameterset_collection_impl.h",
    ],
    features = COMMON_FEATURES,
    tags = ["FUSA"],
    visibility = [
        "@score_config_management//score/config_management/config_daemon/code:__subpackages__",
        "@score_config_management//score:__subpackages__",
    ],
    deps = [
        "@score_baselibs//score/json",
        "@score_baselibs//score/mw/log",
        "@score_config_management//score/config_management/config_daemon/code/data_model:parameter_set_qualifier",
        "@score_config_management//score/config_management/config_daemon/code/data_model:parameterset_collection",
        "@score_config_management//score/config_management/config_daemon/code/data_model/error",
        "@score_baselibs//score/language/futurecpp",
    ],
)

cc_test(
    name = "unit_test",
    srcs = [
        "parameter_set_impl_test.cpp",
        "parameterset_collection_impl_test.cpp",
    ],
    features = COMMON_FEATURES,
    tags = ["unit"],
    visibility = ["@score_config_management//score/config_management/config_daemon/code/data_model:__pkg__"],
    deps = [
        ":parameterset_collection_impl",
        "@score_baselibs//score/json:mock",
        "@googletest//:gtest_main",
    ],
)
