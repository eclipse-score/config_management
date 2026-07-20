load("@rules_cc//cc:defs.bzl", "cc_library")
load("@score_baselibs//:bazel/unit_tests.bzl", "cc_gtest_unit_test")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

cc_library(
    name = "config_calibration_service_reactor_impl",
    srcs = ["config_calibration_service_reactor_impl.cpp"],
    hdrs = ["config_calibration_service_reactor_impl.h"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FFI"],
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        "//score/config_management/config_daemon/code/data_model:parameterset_collection",
        "//score/config_management/config_daemon/code/data_model/error",
        "//score/config_management/config_daemon/code/plugins/calibration/services:config_calibration_service_reactor",
        "//score/config_management/config_daemon/code/plugins/calibration/services/error",
        "//score/config_management/config_daemon/code/plugins/runtime_calibration/calibration_update_observer:interface",
        "//score/config_management/config_daemon/code/services",
        "@score_logging//score/mw/log",
    ],
)

cc_gtest_unit_test(
    name = "unit_test",
    srcs = [
        "config_calibration_service_reactor_test.cpp",
    ],
    features = COMPILER_WARNING_FEATURES,
    visibility = ["//score/config_management/config_daemon/code:__subpackages__"],
    deps = [
        ":config_calibration_service_reactor_impl",
        "//score/config_management/config_daemon/code/data_model:parameterset_collection_mock",
        "//score/config_management/config_daemon/code/plugins/runtime_calibration/calibration_update_observer:mock",
        "//score/config_management/config_daemon/code/services:mock",
        "@googletest//:gtest",
    ],
)
