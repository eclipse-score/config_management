load("@rules_cc//cc:defs.bzl", "cc_library")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")
load("@score_baselibs//:bazel/unit_tests.bzl", "cc_gtest_unit_test", "cc_unit_test_suites_for_host_and_qnx")

cc_library(
    name = "demo_json_plugin_creator",
    srcs = [
        "demo_json_plugin_creator_impl.cpp",
    ],
    hdrs = [
        "demo_json_plugin_creator_impl.h",
    ],
    features = COMPILER_WARNING_FEATURES,
    visibility = ["@score_config_management//score/config_management/config_daemon/code:__subpackages__"],
    deps = [
        "@score_config_management//score/config_management/config_daemon/code/plugins:plugin",
        "@score_config_management//score/config_management/config_daemon/code/plugins:plugin_creator",
        "@score_config_management//score/config_management/config_daemon/code/plugins/demo_json/details:demo_json_plugin_impl",
    ],
)

cc_gtest_unit_test(
    name = "demo_json_plugin_creator_test",
    srcs = [
        "demo_json_plugin_creator_test.cpp",
    ],
    features = COMPILER_WARNING_FEATURES,
    visibility = ["@score_config_management//score/config_management/config_daemon:__subpackages__"],
    deps = [
        ":demo_json_plugin_creator",
        "@score_logging//score/mw/log/test/console_logging_environment",
    ],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [":demo_json_plugin_creator_test"],
    visibility = ["@score_config_management//score/config_management/config_daemon/code/plugins/demo_json:__pkg__"],
)
