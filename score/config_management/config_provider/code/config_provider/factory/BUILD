load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("@score_baselibs//:bazel/unit_tests.bzl", "cc_unit_test_suites_for_host_and_qnx")
load(":custom.bzl", "load_custom_targets")

cc_library(
    name = "factory_mw_com",
    srcs = ["factory_mw_com.cpp"],
    hdrs = ["factory_mw_com.h"],
    features = [
        "treat_warnings_as_errors",
        "additional_warnings",
        "strict_warnings",
    ],
    tags = ["FUSA"],
    visibility = [
        
        "@score_config_management//score/config_management/config_daemon/test:__subpackages__",
        "//score/config_management/config_provider:__subpackages__",
    ],
    deps = [
        "@score_logging//score/mw/log",
        "@score_communication//score/mw/service:factory",
        "@score_communication//score/mw/service/backend/mw_com:single_instantiation_strategy",
        "//score/config_management/config_provider/code/config_provider/details",
        "//score/config_management/config_provider/code/persistency/details:details",
        "//score/config_management/config_provider/code/proxies/details:details_mw_com",
    ],
)

filegroup(
    name = "test_mw_com_config",
    srcs = ["mw_com_config.json"],
)

cc_test(
    name = "unit_tests_mw_com",
    srcs = ["factory_mw_com_test.cpp"],
    data = [":test_mw_com_config"],
    features = [
        "treat_warnings_as_errors",
        "additional_warnings",
        "strict_warnings",
    ],
    tags = [
        "exclusive",  # Sandboxing is not properly working with LoLa message passing 2.0 (Ticket-217341)
        "unit",
    ],
    visibility = [
        "//score/config_management/config_provider:__subpackages__",
    ],
    deps = [
        ":factory_mw_com",
        "//score/config_management/config_provider/code/persistency:mock",
        "@googletest//:gtest_main",
    ],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [
        ":unit_tests_mw_com",
    ],
    visibility = ["//score/config_management/config_provider:__subpackages__"],
)

load_custom_targets()
