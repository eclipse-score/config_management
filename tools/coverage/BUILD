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

load("@score_coverage//:defs.bzl", "score_coverage_reporter", "score_coverage_scope")

# Coverage scope: every production library reachable in CI's wildcard build
# (//score/config_management/... minus the known-broken targets tracked in
# test.yml). Completeness is enforced by .github/tools/check_coverage_scope.sh
# (first step of the coverage workflow): a new production library must be
# added here or justified in tools/coverage/scope_exclusions.txt.
score_coverage_scope(
    name = "coverage_scope",
    testonly = True,
    visibility = ["//visibility:private"],
    deps = [
        "//score/config_management/config_daemon/code/app:interface",
        "//score/config_management/config_daemon/code/app/details:app",
        "//score/config_management/config_daemon/code/data_model:parameter_set_qualifier",
        "//score/config_management/config_daemon/code/data_model:parameterset_collection",
        "//score/config_management/config_daemon/code/data_model:parameterset_collection_manager",
        "//score/config_management/config_daemon/code/data_model/details:parameterset_collection_impl",
        "//score/config_management/config_daemon/code/data_model/details:parameterset_collection_manager_impl",
        "//score/config_management/config_daemon/code/data_model/error",
        "//score/config_management/config_daemon/code/data_model/parameter_set_storage/details:details_score",
        "//score/config_management/config_daemon/code/data_model/parameter_set_storage/details/score_kvs_stub",
        "//score/config_management/config_daemon/code/data_model/parameter_set_storage/error",
        "//score/config_management/config_daemon/code/data_model/parameterset_collection_interfaces:read_only_parameterset_collection",
        "//score/config_management/config_daemon/code/factory:interface",
        "//score/config_management/config_daemon/code/factory/details:mw_factory",
        "//score/config_management/config_daemon/code/fault_event_reporter",
        "//score/config_management/config_daemon/code/fault_event_reporter:fault_event_score_types",
        "//score/config_management/config_daemon/code/fault_event_reporter/details:details_score_impl",
        "//score/config_management/config_daemon/code/json_helper",
        "//score/config_management/config_daemon/code/json_helper/details",
        "//score/config_management/config_daemon/code/plugins:plugin",
        "//score/config_management/config_daemon/code/plugins:plugin_creator",
        "//score/config_management/config_daemon/code/plugins/demo_json/details:demo_json_plugin_impl",
        "//score/config_management/config_daemon/code/plugins/demo_json/parameter_loader:demo_parameter_loader",
        "//score/config_management/config_daemon/code/plugins/demo_json/parameter_loader/details:demo_parameter_loader_impl",
        "//score/config_management/config_daemon/code/plugins/demo_json/plugin_creator:demo_json_plugin_creator",
        "//score/config_management/config_daemon/code/plugins/plugin_collector:interface",
        "//score/config_management/config_daemon/code/plugins/plugin_collector/details",
        "//score/config_management/config_daemon/code/services",
        "//score/config_management/config_daemon/code/services:internal_config_provider_reactor",
        "//score/config_management/config_daemon/code/services/details:details_impl",
        "//score/config_management/config_daemon/code/services/details/mw_com:details_mw_com_impl",
        "//score/config_management/config_daemon/code/services/details/mw_com/generated_service:internal_config_provider_type",
        "//score/config_management/config_daemon/code/types/initial_qualifier_state",
        "//score/config_management/config_provider/code/config_provider",
        "//score/config_management/config_provider/code/config_provider:initial_qualifier_state_types",
        "//score/config_management/config_provider/code/config_provider/error",
        "//score/config_management/config_provider/code/parameter_set",
        "//score/config_management/config_provider/code/persistency",
        "//score/config_management/config_provider/code/persistency/details",
        "//score/config_management/config_provider/code/persistency/error",
        "//score/config_management/config_provider/code/proxies:internal_config_provider",
        "//score/config_management/config_provider/code/proxies/details:details_mw_com",
        "//score/config_management/config_provider/code/proxies/details/mw_com/generated_service:internal_config_provider_type",
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
