load("@rules_cc//cc:defs.bzl", "cc_library")
load("@score_baselibs//:bazel/unit_tests.bzl", "cc_unit_test_suites_for_host_and_qnx")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

cc_library(
    name = "initial_qualifier_container",
    hdrs = ["initial_qualifier_container.h"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FUSA"],
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        "//score/config_management/config_daemon/code/types/initial_qualifier_state",
    ],
)

cc_library(
    name = "mock",
    testonly = True,
    hdrs = ["initial_qualifier_container_mock.h"],
    features = COMPILER_WARNING_FEATURES,
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        ":initial_qualifier_container",
        "@googletest//:gtest",
    ],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [
        "//score/config_management/config_daemon/code/initial_qualifier_container/details:unit_test",
    ],
    visibility = ["//score/config_management/config_daemon/code:__pkg__"],
)
