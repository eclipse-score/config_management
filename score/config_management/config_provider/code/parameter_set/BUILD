load("@score_baselibs//:bazel/unit_tests.bzl", "cc_unit_test_suites_for_host_and_qnx")

COMMON_FEATURES = [
    "treat_warnings_as_errors",
    "strict_warnings",
    "additional_warnings",
]

cc_library(
    name = "parameter_set",
    srcs = ["parameter_set.cpp"],
    hdrs = ["parameter_set.h"],
    features = COMMON_FEATURES,
    tags = ["FUSA"],
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "@score_baselibs//score/json",
        "@score_baselibs//score/mw/log",
        "@score_config_management//score/config_management/config_daemon/code/data_model:parameter_set_qualifier",
        "//score/config_management/config_provider/code/config_provider/error",
    ],
)

cc_test(
    name = "unit_test",
    srcs = [
        "parameter_set_test.cpp",
    ],
    features = COMMON_FEATURES,
    tags = ["unit"],
    visibility = [
        "//score/config_management/config_provider:__subpackages__",
    ],
    deps = [
        ":parameter_set",
        "@score_config_management//score/config_management/config_daemon/code/data_model:parameter_set_qualifier",
        "//score/config_management/config_provider/code/config_provider:config_provider_mock",
        "@googletest//:gtest_main",
    ],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [
        ":unit_test",
    ],
    visibility = ["//score/config_management/config_provider:__subpackages__"],
)
