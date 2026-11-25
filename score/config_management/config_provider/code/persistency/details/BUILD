load("@rules_cc//cc:defs.bzl", "cc_library")
load("@score_baselibs//:bazel/unit_tests.bzl", "cc_gtest_unit_test")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")
load(":custom.bzl", "load_custom_targets")

cc_library(
    name = "details",
    srcs = ["persistency_impl.cpp"],
    hdrs = ["persistency_impl.h"],
    tags = ["FFI"],
    visibility = [
        "//score/config_management/config_provider/code:__subpackages__",
    ],
    deps = [
        "//score/config_management/config_provider/code/persistency",
        "@score_baselibs//score/language/futurecpp",
        "@score_baselibs//score/mw/log:frontend",
    ],
)

cc_gtest_unit_test(
    name = "unit_test",
    srcs = [
        "persistency_impl_test.cpp",
    ],
    features = COMPILER_WARNING_FEATURES,
    visibility = [
        "//score/config_management/config_provider/code/persistency:__pkg__",
    ],
    deps = [
        ":details",
        "@score_baselibs//score/filesystem:mock",
        "@score_baselibs//score/mw/log:console",
    ],
)

load_custom_targets()
