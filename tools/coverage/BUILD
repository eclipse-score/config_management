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

load("@score_tooling//coverage:defs.bzl", "score_coverage_reporter", "score_coverage_scope")

# Coverage scope: every production library of the PUBLIC buildable surface,
# which in this repository is defined by deps_acceptlist.json - the full
# //score tree references targets that only exist in the internal overlay
# (e.g. factory:factory_socal_r20_11, @score_persistency//:kvs_cpp consumers)
# and cannot be analyzed here. Completeness against the acceptlist is
# enforced by .github/tools/check_coverage_scope.sh (first step of the
# coverage workflow): a library added to the acceptlist must be added here
# or justified in tools/coverage/scope_exclusions.txt.
score_coverage_scope(
    name = "coverage_scope",
    testonly = True,
    visibility = ["//visibility:private"],
    deps = [
        "//score/config_management/config_daemon/code/app:interface",
        "//score/config_management/config_daemon/code/data_model:parameter_set_qualifier",
        "//score/config_management/config_daemon/code/data_model:parameterset_collection",
        "//score/config_management/config_daemon/code/data_model/details:parameterset_collection_impl",
        "//score/config_management/config_daemon/code/data_model/error",
        "//score/config_management/config_daemon/code/data_model/parameterset_collection_interfaces:read_only_parameterset_collection",
        "//score/config_management/config_daemon/code/fault_event_reporter",
        "//score/config_management/config_daemon/code/fault_event_reporter:fault_event_score_types",
        "//score/config_management/config_daemon/code/fault_event_reporter/details:details_score_impl",
        "//score/config_management/config_daemon/code/json_helper",
        "//score/config_management/config_daemon/code/json_helper/details",
        "//score/config_management/config_daemon/code/plugins:plugin_creator",
        "//score/config_management/config_daemon/code/services:internal_config_provider_reactor",
        "//score/config_management/config_daemon/code/types/initial_qualifier_state",
        "//score/config_management/config_provider/code/config_provider/error",
        "//score/config_management/config_provider/code/parameter_set",
        "//score/config_management/config_provider/code/persistency/error",
    ],
)

score_coverage_reporter(
    name = "reporter_wrapper",
    testonly = True,
    coverage_scope = ":coverage_scope",
    llvm_cov = "@llvm_toolchain_coverage//:llvm-cov",
    llvm_cxxfilt = "@llvm_toolchain_coverage_llvm//:bin/llvm-cxxfilt",
    llvm_profdata = "@llvm_toolchain_coverage//:llvm-profdata",
    visibility = ["//visibility:public"],
)
