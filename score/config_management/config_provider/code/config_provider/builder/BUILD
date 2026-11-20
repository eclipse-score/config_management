load("@rules_cc//cc:defs.bzl", "cc_library")
load("@score_baselibs//:bazel/unit_tests.bzl", "cc_unit_test_suites_for_host_and_qnx")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

cc_library(
    name = "config_provider_builder",
    hdrs = ["config_provider_builder.h"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FUSA"],
    visibility = [
        "//score/config_management/config_provider:__subpackages__",
    ],
    deps = [
        "//score/config_management/config_provider/code/config_provider",
        "//score/config_management/config_provider/code/persistency",
        "//score/config_management/config_provider/code/proxies:internal_config_provider",
        "@score_baselibs//score/language/futurecpp",
        "@score_communication//score/mw/service:find_service_strategy",
    ],
)

cc_library(
    name = "mock",
    testonly = True,
    hdrs = ["config_provider_builder_mock.h"],
    features = COMPILER_WARNING_FEATURES,
    visibility = [
        "//score/config_management/config_provider:__subpackages__",
    ],
    deps = [
        ":config_provider_builder",
        "@googletest//:gtest",
    ],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [
        "//score/config_management/config_provider/code/config_provider/builder/details:unit_test",
    ],
    visibility = ["//score/config_management/config_provider:__subpackages__"],
)
