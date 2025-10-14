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

cc_library(
    name = "read_only_parameterset_collection",
    srcs = [
        "read_only_parameterset_collection.cpp",
    ],
    hdrs = [
        "read_only_parameterset_collection.h",
    ],
    features = [
        "treat_warnings_as_errors",
        "additional_warnings",
        "strict_warnings",
    ],
    tags = ["FFI"],
    visibility = ["@score-config_management//score/config_management/config_daemon:__subpackages__"],
    deps = [
        "@score-baselibs//score/json",
        "@score-baselibs//score/result",
        "@score-baselibs//score/language/futurecpp",
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
    features = [
        "treat_warnings_as_errors",
        "additional_warnings",
        "strict_warnings",
    ],
    deps = [
        ":read_only_parameterset_collection",
        "@googletest//:gtest",
    ],
)
