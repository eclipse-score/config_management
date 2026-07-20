load("@rules_cc//cc:defs.bzl", "cc_library")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

cc_library(
    name = "parameter_loader",
    srcs = [
        "parameter_loader.cpp",
    ],
    hdrs = [
        "parameter_loader.h",
    ],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FFI"],
    visibility = [
        "//score/config_management/config_daemon/code/plugins/calibration:__subpackages__",
        "//score/config_management/config_daemon/code/plugins/calibration_loader:__subpackages__",
    ],
    deps = [
        "//platform/aas/mw/diag/dtc",
        "//score/config_management/config_daemon/code/data_model:parameterset_collection",
        "//score/config_management/config_daemon/code/data_model/error",
        "@score_baselibs//score/language/futurecpp",
    ],
)

cc_library(
    name = "parameter_loader_mock",
    testonly = True,
    srcs = [
        "parameter_loader_mock.cpp",
    ],
    hdrs = [
        "parameter_loader_mock.h",
    ],
    features = COMPILER_WARNING_FEATURES,
    visibility = [
        "//score/config_management/config_daemon/code/plugins/calibration:__subpackages__",
        "//score/config_management/config_daemon/code/plugins/calibration_loader:__subpackages__",
    ],
    deps = [
        ":parameter_loader",
        "@googletest//:gtest",
    ],
)
