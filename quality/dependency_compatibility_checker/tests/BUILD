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

load("@rules_python//python:defs.bzl", "py_test")

py_test(
    name = "test_config_schema",
    srcs = ["test_config_schema.py"],
    main = "test_config_schema.py",
    deps = ["//quality/dependency_compatibility_checker:config_schema"],
)

py_test(
    name = "test_generate_matrix",
    srcs = ["test_generate_matrix.py"],
    main = "test_generate_matrix.py",
    deps = ["//quality/dependency_compatibility_checker:generate_matrix"],
)

py_test(
    name = "test_module_rewriter",
    srcs = ["test_module_rewriter.py"],
    data = glob(["fixtures/*.MODULE"]),
    main = "test_module_rewriter.py",
    deps = ["//quality/dependency_compatibility_checker:module_rewriter"],
)

py_test(
    name = "test_resolve_config",
    srcs = ["test_resolve_config.py"],
    main = "test_resolve_config.py",
    deps = ["//quality/dependency_compatibility_checker:resolve_config"],
)

py_test(
    name = "test_generate_report",
    srcs = ["test_generate_report.py"],
    main = "test_generate_report.py",
    deps = ["//quality/dependency_compatibility_checker:generate_report"],
)
