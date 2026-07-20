load("@rules_cc//cc:defs.bzl", "cc_library")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

cc_library(
    name = "service_toggler_interface",
    srcs = [
        "service_toggler.cpp",
    ],
    hdrs = [
        "service_toggler.h",
    ],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FFI"],
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
    ],
)

cc_library(
    name = "service_toggler_mock",
    srcs = [
        "service_toggler_mock.cpp",
    ],
    hdrs = [
        "service_toggler_mock.h",
    ],
    features = COMPILER_WARNING_FEATURES,
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        ":service_toggler_interface",
        "@googletest//:gtest",
    ],
)
