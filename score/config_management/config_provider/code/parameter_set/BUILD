load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("@score_baselibs//:bazel/unit_tests.bzl", "cc_unit_test_suites_for_host_and_qnx")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

cc_library(
    name = "parameter_set",
    srcs = ["parameter_set.cpp"],
    hdrs = ["parameter_set.h"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FUSA"],
    visibility = [
        "//score/config_management/config_provider:__subpackages__",
    ],
    deps = [
        "//score/config_management/config_daemon/code/data_model:parameter_set_qualifier",
        "//score/config_management/config_provider/code/config_provider/error",
        "@score_baselibs//score/json",
        "@score_logging//score/mw/log",
    ],
)

cc_test(
    name = "unit_test",
    srcs = [
        "parameter_set_test.cpp",
    ],
    features = COMPILER_WARNING_FEATURES,
    tags = ["unit"],
    visibility = [
        "//score/config_management/config_provider:__subpackages__",
    ],
    deps = [
        ":parameter_set",
        "//score/config_management/config_daemon/code/data_model:parameter_set_qualifier",
        "//score/config_management/config_provider:config_provider_mock",
        "@googletest//:gtest_main",
        "@score_logging//score/mw/log/test/console_logging_environment",
    ],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [
        ":unit_test",
    ],
    visibility = ["//score/config_management/config_provider:__subpackages__"],
)
