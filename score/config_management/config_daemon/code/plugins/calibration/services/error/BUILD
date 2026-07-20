load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

cc_library(
    name = "error",
    srcs = ["update_parameter_set_error_domain.cpp"],
    hdrs = ["update_parameter_set_error_domain.h"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FFI"],
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        "@score_baselibs//score/result",
    ],
)

cc_test(
    name = "unit_test",
    srcs = ["update_parameter_set_error_domain_test.cpp"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["unit"],
    visibility = ["//score/config_management/config_daemon/code:__subpackages__"],
    deps = [
        ":error",
        "@googletest//:gtest_main",
    ],
)
