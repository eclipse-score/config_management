load("@score_baselibs//:bazel/unit_tests.bzl", "cc_unit_test_suites_for_host_and_qnx")
load("@score_baselibs//score/quality/clang_tidy:extra_checks.bzl", "clang_tidy_extra_checks")

cc_library(
    name = "ConfigProvider",
    tags = ["FUSA"],
    visibility = ["//visibility:public"],
    deps = ["//score/config_management/config_provider/code/config_provider/factory:factory_mw_com"],
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

clang_tidy_extra_checks(
    name = "clang_tidy_extra_checks",
    extra_features = [
        "spp_code_style_check_header_guards",
        "spp_code_style_check_method_names",
        "spp_code_style_check_readability",
        "spp_code_style_check_variable_names",
        "spp_code_style_check_type_names",
    ],
)
