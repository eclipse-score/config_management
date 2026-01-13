load("@score_baselibs//:bazel/unit_tests.bzl", "cc_unit_test_suites_for_host_and_qnx")

cc_library(
    name = "internal_config_provider",
    srcs = ["internal_config_provider.cpp"],
    hdrs = ["internal_config_provider.h"],
    features = [
        "treat_warnings_as_errors",
        "additional_warnings",
        "strict_warnings",
    ],
    tags = ["FUSA"],
    visibility = [
        "//visibility:public",  # platform_only
    ],
    deps = [
        "@score_baselibs//score/json",
        "//score/config_management/config_provider/code/config_provider:initial_qualifier_state_types",
        "//score/config_management/config_provider/code/config_provider/error",
        "@score_baselibs//score/language/futurecpp",
    ],
)

cc_library(
    name = "mock",
    hdrs = ["internal_config_provider_mock.h"],
    features = [
        "treat_warnings_as_errors",
        "additional_warnings",
        "strict_warnings",
    ],
    visibility = [
        "//visibility:public",  # platform_only
    ],
    deps = [
        ":internal_config_provider",
        "@googletest//:gtest",
    ],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [
        "//score/config_management/config_provider/code/proxies/details:unit_test_mw",
    ],
    visibility = ["//score/config_management/config_provider:__subpackages__"],
)
