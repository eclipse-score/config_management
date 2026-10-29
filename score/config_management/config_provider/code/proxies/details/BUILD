load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")
load(":custom.bzl", "load_custom_targets")

# MW COM proxy implementation (always exported to open-source)
cc_library(
    name = "details_mw_com",
    srcs = ["mw_com/internal_config_provider_impl.cpp"],
    hdrs = ["mw_com/internal_config_provider_impl.h"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FUSA"],
    visibility = [
        "//score/config_management/config_provider:__subpackages__",
    ],
    deps = [
        "//score/config_management/config_provider/code/config_provider/factory:buffer_size_report",
        "//score/config_management/config_provider/code/proxies:internal_config_provider",
        "//score/config_management/lib/mw_com_types:internal_config_provider_type",
        "@score_baselibs//score/concurrency:condition_variable",
        "@score_baselibs//score/concurrency/future",
        "@score_baselibs//score/json",
        "@score_baselibs//score/json:json_parser",
        "@score_logging//score/mw/log",
    ],
)

filegroup(
    name = "test_mw_com_config",
    testonly = True,
    srcs = ["mw_com/test_mw_com_config.json"],
    visibility = ["//score/config_management/config_provider:__subpackages__"],
)

# MW COM unit test
cc_test(
    name = "unit_test_mw",
    srcs = ["mw_com/internal_config_provider_impl_test.cpp"],
    data = [":test_mw_com_config"],
    features = COMPILER_WARNING_FEATURES,
    tags = [
        "exclusive",  # Sandboxing is not properly working with LoLa message passing 2.0 (Ticket-217341)
        "unit",
    ],
    visibility = ["//score/config_management/config_provider/code/proxies:__pkg__"],
    deps = [
        ":details_mw_com",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
        "@rules_cc//cc/runfiles",
        "@score_baselibs//score/concurrency:notification",
    ],
)

# Load ARA COM proxy targets (will be stubbed in open-source)
load_custom_targets()
