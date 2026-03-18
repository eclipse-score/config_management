load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

cc_library(
    name = "error",
    srcs = [
        "persistency_error.cpp",
    ],
    hdrs = [
        "persistency_error.h",
    ],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FFI"],
    visibility = ["//score/config_management/config_provider/code:__subpackages__"],
    deps = [
        "@score_baselibs//score/result",
    ],
)

cc_test(
    name = "unit_test",
    srcs = [
        "persistency_error_test.cpp",
    ],
    features = COMPILER_WARNING_FEATURES,
    tags = ["unit"],
    visibility = ["//score/config_management/config_provider/code/persistency:__pkg__"],
    deps = [
        ":error",
        "@googletest//:gtest_main",
    ],
)
