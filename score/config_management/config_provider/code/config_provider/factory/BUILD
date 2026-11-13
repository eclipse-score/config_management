load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("@score_baselibs//:bazel/unit_tests.bzl", "cc_gtest_unit_test", "cc_unit_test_suites_for_host_and_qnx")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

cc_library(
    name = "semi_dynamic_single_instantiation_strategy",
    hdrs = ["semi_dynamic_single_instantiation_strategy.h"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FUSA"],
    visibility = [
        "//score/config_management/config_provider:__subpackages__",
    ],
    deps = [
        "@score_baselibs//score/language/futurecpp",
        "@score_communication//score/mw/com",
        "@score_communication//score/mw/service:find_service_strategy",
        "@score_communication//score/mw/service:proxy_builder_base",
        "@score_logging//score/mw/log",
    ],
)

cc_library(
    name = "buffer_size_report",
    srcs = ["buffer_size_report.cpp"],
    hdrs = ["buffer_size_report.h"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FUSA"],
    visibility = [
        "//score/config_management/config_provider:__subpackages__",
    ],
    deps = [
        "//score/config_management/config_provider/code/config_provider/error",
        "//score/config_management/lib/mw_com_types:internal_config_provider_type",
        "@score_baselibs//score/json",
        "@score_baselibs//score/language/futurecpp",
        "@score_baselibs//score/result",
        "@score_logging//score/mw/log",
    ],
)

cc_gtest_unit_test(
    name = "unit_tests_buffer_size_report",
    srcs = ["buffer_size_report_test.cpp"],
    features = COMPILER_WARNING_FEATURES,
    visibility = [
        "//score/config_management/config_provider:__subpackages__",
    ],
    deps = [
        ":buffer_size_report",
        "@score_baselibs//score/json:mock",
        "@score_baselibs//score/language/futurecpp",
    ],
)

cc_library(
    name = "factory_mw_com_for_unit_test",
    testonly = True,
    hdrs = ["fake/factory_mw_com.h"],
    features = COMPILER_WARNING_FEATURES,
    include_prefix = "score/config_management/config_provider/code/config_provider/factory",
    strip_include_prefix = "fake",
    visibility = [
        "//score/config_management/config_provider:__subpackages__",
    ],
    deps = [
        ":buffer_size_report",
        "//score/config_management/config_provider/code/config_provider",
        "//score/config_management/config_provider/code/config_provider:config_provider_mock",
        "//score/config_management/config_provider/code/config_provider/error",
        "//score/config_management/config_provider/code/persistency",
        "//score/config_management/config_provider/code/proxies:internal_config_provider",
        "@googletest//:gtest",
        "@score_baselibs//score/language/futurecpp",
        "@score_communication//score/mw/service:find_service_strategy",
    ],
)

cc_library(
    name = "factory_mw_com",
    srcs = ["details/factory_mw_com.cpp"],
    hdrs = ["details/factory_mw_com.h"],
    features = COMPILER_WARNING_FEATURES,
    include_prefix = "score/config_management/config_provider/code/config_provider/factory",
    strip_include_prefix = "details",
    tags = ["FUSA"],
    visibility = [
        "//score/config_management/config_provider:__subpackages__",
    ],
    deps = [
        ":buffer_size_report",
        ":semi_dynamic_single_instantiation_strategy",
        "//score/config_management/config_provider/code/config_provider/details",
        "//score/config_management/config_provider/code/persistency/details",
        "//score/config_management/config_provider/code/proxies/details:details_mw_com",
        "@score_baselibs//score/json",
        "@score_communication//score/mw/service:factory",
        "@score_communication//score/mw/service/backend/mw_com:single_instantiation_strategy",
        "@score_logging//score/mw/log",
    ],
)

cc_test(
    name = "unit_tests_mw_com",
    srcs = ["factory_mw_com_test.cpp"],
    features = COMPILER_WARNING_FEATURES,
    tags = [
        "unit",
    ],
    visibility = [
        "//score/config_management/config_provider:__subpackages__",
    ],
    deps = [
        ":factory_mw_com",
        ":semi_dynamic_single_instantiation_strategy",
        "//score/config_management/config_provider/code/config_provider/error",
        "//score/config_management/config_provider/code/persistency:mock",
        "//score/config_management/config_provider/code/proxies:internal_config_provider",
        "//score/config_management/config_provider/code/proxies:mock",
        "@googletest//:gtest_main",
        "@score_baselibs//score/json",
    ],
)

cc_gtest_unit_test(
    name = "unit_tests_semi_dynamic_single_instantiation_strategy",
    srcs = ["semi_dynamic_single_instantiation_strategy_test.cpp"],
    features = COMPILER_WARNING_FEATURES,
    visibility = [
        "//score/config_management/config_provider:__subpackages__",
    ],
    deps = [
        ":semi_dynamic_single_instantiation_strategy",
        "@score_baselibs//score/concurrency/future",
        "@score_baselibs//score/result",
        "@score_communication//score/mw/com",
        "@score_communication//score/mw/service:proxy_builder_base",
        "@score_communication//score/mw/service:single_instance_holder",
    ],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [],
    visibility = ["//score/config_management/config_provider:__subpackages__"],
)
