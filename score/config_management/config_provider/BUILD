load("@rules_cc//cc:defs.bzl", "cc_library")
load("@score_baselibs//:bazel/unit_tests.bzl", "cc_unit_test_suites_for_host_and_qnx")
load("@score_baselibs//score/quality/clang_tidy:extra_checks.bzl", "clang_tidy_extra_checks")

clang_tidy_extra_checks(
    name = "clang_tidy_extra_checks",
)

alias(
    name = "config_provider_interface",
    actual = "//score/config_management/config_provider/code/config_provider",
    visibility = ["//visibility:public"],
)

alias(
    name = "config_provider_mock",
    actual = "//score/config_management/config_provider/code/config_provider:config_provider_mock",
    visibility = ["//visibility:public"],
)

cc_library(
    name = "config_provider_factory_impl",
    tags = ["FUSA"],
    visibility = ["//visibility:public"],
    deps = ["//score/config_management/config_provider/code/config_provider/factory:factory_mw_com"],
)

alias(
    name = "config_provider_factory_for_unit_test",
    actual = "//score/config_management/config_provider/code/config_provider/factory:factory_mw_com_for_unit_test",
    visibility = ["//visibility:public"],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    test_suites_from_sub_packages = [
        "//score/config_management/config_provider/code/config_provider:unit_tests",
        "//score/config_management/config_provider/code/parameter_set:unit_tests",
        "//score/config_management/config_provider/code/persistency:unit_tests",
        "//score/config_management/config_provider/code/proxies:unit_tests",
    ],
    visibility = ["//score/config_management:__pkg__"],
)

test_suite(
    name = "component_tests",
    tests = [],
    visibility = ["//score/config_management:__pkg__"],
)
