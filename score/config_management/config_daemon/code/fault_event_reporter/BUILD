load("@score-baselibs//:bazel/unit_tests.bzl", "cc_unit_test_suites_for_host_and_qnx")

cc_library(
    name = "fault_event_reporter",
    srcs = [
        "fault_event_reporter.cpp",
    ],
    hdrs = [
        "fault_event_reporter.h",
    ],
    features = [
        "treat_warnings_as_errors",
        "additional_warnings",
        "strict_warnings",
    ],
    tags = ["FFI"],
    visibility = [
        "@score-config_management//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
    ],
)

cc_library(
    name = "mock",
    testonly = True,
    hdrs = [
        "fault_event_reporter_mock.h",
    ],
    features = [
        "treat_warnings_as_errors",
        "additional_warnings",
        "strict_warnings",
    ],
    visibility = [
        "@score-config_management//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        ":fault_event_reporter",
        "@googletest//:gtest",
    ],
)

cc_library(
    name = "fault_event_score_types",
    hdrs = ["fault_event_score_types.h"],
    features = [
        "treat_warnings_as_errors",
        "additional_warnings",
        "strict_warnings",
    ],
    tags = ["FFI"],
    visibility = [
        "@score-config_management//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [
        "@score-config_management//score/config_management/config_daemon/code/fault_event_reporter/details:unit_test",
    ],
    visibility = ["@score-config_management//score/config_management/config_daemon/code:__subpackages__"],
)
