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

load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

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
        "@score_config_management//score/config_management/config_daemon/code:__subpackages__",
        "@score_config_management//score/config_management/config_daemon/test:__subpackages__",
        "//score/config_management/config_provider:__subpackages__",
    ],
    deps = [
        "@score_communication//score/mw/com",
    ],
)
