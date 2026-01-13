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

COMMON_FEATURES = [
    "treat_warnings_as_errors",
    "strict_warnings",
    "additional_warnings",
]

cc_library(
    name = "initial_qualifier_state",
    testonly = False,
    srcs = ["initial_qualifier_state.cpp"],
    hdrs = ["initial_qualifier_state.h"],
    features = COMMON_FEATURES,
    tags = ["FUSA"],
    visibility = [
        "@score_config_management//score/config_management/config_daemon/code:__subpackages__",
    ],
)
