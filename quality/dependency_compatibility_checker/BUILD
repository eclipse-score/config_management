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

load("@rules_python//python:defs.bzl", "py_binary", "py_library")

py_library(
    name = "config_schema",
    srcs = ["config_schema.py"],
    visibility = ["//:__subpackages__"],
    deps = ["@config_management_pip//pyyaml"],
)

py_binary(
    name = "resolve_config",
    srcs = ["resolve_config.py"],
    visibility = ["//:__subpackages__"],
    deps = [
        ":config_schema",
        ":module_rewriter",
        "@config_management_pip//pyyaml",
    ],
)

py_binary(
    name = "generate_matrix",
    srcs = ["generate_matrix.py"],
    visibility = ["//:__subpackages__"],
    deps = [":config_schema"],
)

py_binary(
    name = "module_rewriter",
    srcs = ["module_rewriter.py"],
    visibility = ["//:__subpackages__"],
    deps = [":config_schema"],
)

py_binary(
    name = "generate_report",
    srcs = ["generate_report.py"],
    data = ["report.html.j2"],
    visibility = ["//:__subpackages__"],
    deps = [
        ":config_schema",
        "@config_management_pip//jinja2",
        "@config_management_pip//markupsafe",
    ],
)
