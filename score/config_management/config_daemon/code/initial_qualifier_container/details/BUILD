load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

cc_library(
    name = "details",
    srcs = ["initial_qualifier_container_impl.cpp"],
    hdrs = ["initial_qualifier_container_impl.h"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FUSA"],
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        "//score/config_management/config_daemon/code/initial_qualifier_container",
        "@score_baselibs//score/language/futurecpp",
        "@score_logging//score/mw/log",
    ],
)

cc_test(
    name = "unit_test",
    srcs = ["initial_qualifier_container_impl_test.cpp"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["unit"],
    visibility = [
        "//score/config_management/config_daemon:__subpackages__",
    ],
    deps = [
        ":details",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)
