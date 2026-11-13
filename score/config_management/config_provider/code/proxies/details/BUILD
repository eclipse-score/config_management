load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

cc_library(
    name = "internal_config_provider_proxy",
    hdrs = ["internal_config_provider_proxy.h"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FUSA"],
    visibility = ["//score/config_management/config_provider:__subpackages__"],
    deps = [
        "//score/config_management/lib/mw_com_types:internal_config_provider_type",
        "@score_communication//score/mw/com",
    ],
)

cc_library(
    name = "internal_config_provider_proxy_fake_for_unit_test",
    testonly = True,
    hdrs = ["fake/internal_config_provider_proxy.h"],
    features = COMPILER_WARNING_FEATURES,
    include_prefix = "score/config_management/config_provider/code/proxies/details",
    strip_include_prefix = "fake",
    visibility = ["//score/config_management/config_provider:__subpackages__"],
    deps = [
        "//score/config_management/lib/mw_com_types:internal_config_provider_type",
        "@score_baselibs//score/result",
        "@score_communication//score/memory/shared:polymorphic_offset_ptr_allocator",
        "@score_communication//score/mw/com",
    ],
)

[
    cc_library(
        name = "details_mw_com" + suffix,
        testonly = test_only,
        srcs = ["internal_config_provider_impl.cpp"],
        hdrs = ["internal_config_provider_impl.h"],
        features = COMPILER_WARNING_FEATURES,
        tags = ["FUSA"],
        visibility = [
            "//score/config_management/config_provider:__subpackages__",
        ],
        deps = [
            proxy_dep,
            "//score/config_management/config_provider/code/config_provider/factory:buffer_size_report",
            "//score/config_management/config_provider/code/proxies:internal_config_provider",
            "//score/config_management/lib/mw_com_types:internal_config_provider_type",
            "@score_baselibs//score/concurrency:condition_variable",
            "@score_baselibs//score/concurrency/future",
            "@score_baselibs//score/json",
            "@score_logging//score/mw/log",
        ],
    )
    for suffix, test_only, proxy_dep in [
        # MW COM proxy implementation (always exported to open-source)
        ("", False, ":internal_config_provider_proxy"),
        ("_for_unit_test", True, ":internal_config_provider_proxy_fake_for_unit_test"),
    ]
]

# MW COM unit test, runs the real InternalConfigProvider logic against an in-memory fake proxy
cc_test(
    name = "unit_test_mw",
    srcs = ["internal_config_provider_impl_test.cpp"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["unit"],
    visibility = ["//score/config_management/config_provider/code/proxies:__pkg__"],
    deps = [
        ":details_mw_com_for_unit_test",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
        "@score_baselibs//score/concurrency:notification",
    ],
)
