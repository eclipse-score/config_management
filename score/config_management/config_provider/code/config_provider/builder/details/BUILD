load("@rules_cc//cc:defs.bzl", "cc_library")
load("@score_baselibs//:bazel/unit_tests.bzl", "cc_gtest_unit_test")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

cc_library(
    name = "details",
    hdrs = ["config_provider_builder_impl.h"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FUSA"],
    visibility = [
        "//score/config_management/config_provider:__subpackages__",
    ],
    deps = [
        "//score/config_management/config_provider/code/config_provider/builder:config_provider_builder",
        "//score/config_management/config_provider/code/config_provider/details",
        "//score/config_management/config_provider/code/config_provider/factory:buffer_size_report",
        "//score/config_management/config_provider/code/config_provider/factory:semi_dynamic_single_instantiation_strategy",
        "//score/config_management/config_provider/code/persistency/details",
        "//score/config_management/config_provider/code/proxies/details:details_mw_com",
        "@score_baselibs//score/json",
        "@score_baselibs//score/mw/log:frontend",
        "@score_communication//score/mw/service:factory",
        "@score_communication//score/mw/service/backend/mw_com:single_instantiation_strategy",
    ],
)

cc_gtest_unit_test(
    name = "unit_test",
    srcs = ["config_provider_builder_impl_test.cpp"],
    features = COMPILER_WARNING_FEATURES,
    visibility = [
        "//score/config_management/config_provider:__subpackages__",
    ],
    deps = [
        ":details",
        "//score/config_management/config_provider/code/config_provider/builder:mock",
        "//score/config_management/config_provider/code/config_provider/error",
        "//score/config_management/config_provider/code/config_provider/factory:semi_dynamic_single_instantiation_strategy",
        "//score/config_management/config_provider/code/persistency:mock",
        "//score/config_management/config_provider/code/proxies:internal_config_provider",
        "//score/config_management/config_provider/code/proxies:mock",
        "@score_baselibs//score/json",
    ],
)
