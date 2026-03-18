load("@rules_cc//cc:defs.bzl", "cc_library")
load("@score_baselibs//:bazel/unit_tests.bzl", "cc_unit_test_suites_for_host_and_qnx")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")
load(":custom.bzl", "load_custom_test_suites")

cc_library(
    name = "fault_event_reporter",
    srcs = [
        "fault_event_reporter.cpp",
    ],
    hdrs = [
        "fault_event_reporter.h",
    ],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FFI"],
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        "@score_baselibs//score/result",
    ],
)

cc_library(
    name = "mock",
    testonly = True,
    hdrs = [
        "fault_event_reporter_mock.h",
    ],
    features = COMPILER_WARNING_FEATURES,
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        ":fault_event_reporter",
        "@googletest//:gtest",
    ],
)

cc_library(
    name = "fault_event_types",
    hdrs = ["fault_event_bmw_types.h"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FFI"],
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [],
)

cc_library(
    name = "fault_event_score_types",
    hdrs = ["fault_event_score_types.h"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FFI"],
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [
        "//score/config_management/config_daemon/code/fault_event_reporter/details:score_impl_unit_test",
    ] + load_custom_test_suites(),
    visibility = ["//score/config_management/config_daemon/code:__subpackages__"],
)
