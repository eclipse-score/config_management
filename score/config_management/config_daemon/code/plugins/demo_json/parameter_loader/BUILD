load("@rules_cc//cc:defs.bzl", "cc_library")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

cc_library(
    name = "demo_parameter_loader",
    srcs = [
        "demo_parameter_loader.cpp",
    ],
    hdrs = [
        "demo_parameter_loader.h",
    ],
    features = COMPILER_WARNING_FEATURES,
    visibility = ["//score/config_management/config_daemon/code:__subpackages__"],
    deps = [
        "//score/config_management/config_daemon/code/data_model:parameterset_collection",
    ],
)
