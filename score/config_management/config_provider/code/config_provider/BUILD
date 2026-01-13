load("@score_baselibs//:bazel/unit_tests.bzl", "cc_unit_test_suites_for_host_and_qnx")

cc_library(
    name = "initial_qualifier_state_types",
    srcs = ["initial_qualifier_state_types.cpp"],
    hdrs = ["initial_qualifier_state_types.h"],
    features = [
        "treat_warnings_as_errors",
        "additional_warnings",
        "strict_warnings",
    ],
    tags = ["FUSA"],
    visibility = [
        "//visibility:public",
    ],
    deps = ["@score_baselibs//score/language/futurecpp"],
)

cc_library(
    name = "config_provider",
    srcs = ["config_provider.cpp"],
    hdrs = ["config_provider.h"],
    features = [
        "treat_warnings_as_errors",
        "additional_warnings",
        "strict_warnings",
    ],
    tags = ["FUSA"],
    visibility = [
        "//visibility:public",
    ],
    deps = [
        ":initial_qualifier_state_types",
        "//score/config_management/config_provider/code/parameter_set",
        "@score_baselibs//score/language/futurecpp",
    ],
)

cc_library(
    name = "config_provider_mock",
    srcs = ["config_provider_mock.cpp"],
    hdrs = ["config_provider_mock.h"],
    features = [
        "treat_warnings_as_errors",
        "additional_warnings",
        "strict_warnings",
    ],
    visibility = [
        "//visibility:public",
    ],
    deps = [
        ":config_provider",
        "//score/config_management/config_provider/code/parameter_set",
        "@googletest//:gtest",
        "@score_baselibs//score/language/futurecpp",
    ],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    test_suites_from_sub_packages = [
        "//score/config_management/config_provider/code/config_provider/details:unit_tests",
        "//score/config_management/config_provider/code/config_provider/error:unit_tests",
        "//score/config_management/config_provider/code/config_provider/factory:unit_tests",
    ],
    visibility = ["//score/config_management/config_provider:__subpackages__"],
)
