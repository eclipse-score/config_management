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
        "//score/config_management/config_daemon/test/xpad_ara_com_mock:__subpackages__",
        "//score/config_management/config_provider:__subpackages__",
    ],
    deps = [
        "//score/config_management/config_provider/code/proxies:internal_config_provider",
        "//score/config_management/config_provider/code/proxies/details/mw_com/generated_service:internal_config_provider_type",
        "@score_baselibs//score/concurrency:condition_variable",
        "@score_baselibs//score/concurrency/future",
        "@score_baselibs//score/json",
        "@score_logging//score/mw/log",
    ],
)

filegroup(
    name = "test_mw_com_config",
    srcs = ["mw_com/mw_com_config.json"],
    visibility = ["//score/config_management/config_provider:__subpackages__"],
)

# MW COM unit test
cc_test(
    name = "unit_test_mw",
    srcs = ["mw_com/internal_config_provider_impl_test.cpp"],
    data = [":test_mw_com_config"],
    features = COMPILER_WARNING_FEATURES,
    visibility = ["//score/config_management/config_provider/code/proxies:__pkg__"],
    deps = [
        ":details_mw_com",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)

# Load ARA COM proxy targets (will be stubbed in open-source)
load_custom_targets()
