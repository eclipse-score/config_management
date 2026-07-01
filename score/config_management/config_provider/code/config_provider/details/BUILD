load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("@score_baselibs//:bazel/unit_tests.bzl", "cc_unit_test_suites_for_host_and_qnx")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

cc_library(
    name = "details",
    srcs = [
        "config_provider_impl.cpp",
    ],
    hdrs = [
        "config_provider_impl.h",
    ],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FUSA"],
    visibility = ["//score/config_management/config_provider:__subpackages__"],
    deps = [
        "//score/config_management/config_provider/code/config_provider",
        "//score/config_management/config_provider/code/config_provider/error",
        "//score/config_management/config_provider/code/persistency",
        "//score/config_management/config_provider/code/proxies:internal_config_provider",
        "@score_baselibs//score/concurrency:condition_variable",
        "@score_baselibs//score/concurrency/future",
        "@score_baselibs//score/language/futurecpp",
        "@score_communication//score/mw/service:proxy_data",
        "@score_logging//score/mw/log",
    ],
)

cc_test(
    name = "unit_test",
    srcs = [
        "config_provider_impl_test.cpp",
    ],
    features = COMPILER_WARNING_FEATURES,
    tags = ["unit"],
    visibility = [
        "//score/config_management/config_provider:__subpackages__",
    ],
    deps = [
        ":details",
        "//score/config_management/config_provider/code/config_provider/error",
        "//score/config_management/config_provider/code/persistency:mock",
        "//score/config_management/config_provider/code/persistency/error",
        "//score/config_management/config_provider/code/proxies:mock",
        "@googletest//:gtest_main",
        "@score_baselibs//score/concurrency:notification",
        "@score_baselibs//score/mw/log:recorder_mock",
    ],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [
        ":unit_test",
    ],
    visibility = ["//score/config_management/config_provider:__subpackages__"],
)
