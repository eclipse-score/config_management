load("@rules_cc//cc:defs.bzl", "cc_library")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")
load("@score_baselibs//:bazel/unit_tests.bzl", "cc_gtest_unit_test", "cc_unit_test_suites_for_host_and_qnx")

cc_library(
    name = "demo_parameter_loader_impl",
    srcs = [
        "demo_parameter_loader_impl.cpp",
    ],
    hdrs = [
        "demo_parameter_loader_impl.h",
    ],
    features = COMPILER_WARNING_FEATURES,
    visibility = ["//score/config_management/config_daemon/code:__subpackages__"],
    deps = [
        "@score_baselibs//score/json:json_serializer",
        "@score_logging//score/mw/log",
        "//score/config_management/config_daemon/code/data_model:parameterset_collection",
        "//score/config_management/config_daemon/code/plugins/demo_json/parameter_loader:demo_parameter_loader",
        "@score_baselibs//score/language/futurecpp",
    ],
)

cc_gtest_unit_test(
    name = "demo_parameter_loader_impl_test",
    srcs = [
        "demo_parameter_loader_impl_test.cpp",
    ],
    features = COMPILER_WARNING_FEATURES,
    visibility = ["//score/config_management/config_daemon:__subpackages__"],
    deps = [
        ":demo_parameter_loader_impl",
        "@score_baselibs//score/json:json_impl",
        "@score_logging//score/mw/log/test/console_logging_environment",
        "//score/config_management/config_daemon/code/data_model:parameterset_collection_mock",
        "//score/config_management/config_daemon/code/data_model/details:parameterset_collection_impl",
        "//score/config_management/config_daemon/code/data_model/error",
    ],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [":demo_parameter_loader_impl_test"],
    visibility = ["//score/config_management/config_daemon/code/plugins/demo_json:__pkg__"],
)
