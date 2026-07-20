load("@rules_cc//cc:defs.bzl", "cc_library")
load("@score_baselibs//:bazel/unit_tests.bzl", "cc_unit_test_suites_for_host_and_qnx")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

cc_library(
    name = "calibration_mock",
    testonly = True,
    srcs = [
        "calibration_mock.cpp",
    ],
    hdrs = [
        "calibration_mock.h",
    ],
    features = COMPILER_WARNING_FEATURES,
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        "//score/config_management/config_daemon/code/plugins:plugin",
        "@googletest//:gtest",
    ],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [
        "//score/config_management/config_daemon/code/plugins/calibration/details:calibration_test",
    ],
    test_suites_from_sub_packages = [
        "//score/config_management/config_daemon/code/plugins/calibration/error:unit_tests",
        "//score/config_management/config_daemon/code/plugins/calibration/parameter_loader/details:unit_tests",
        "//score/config_management/config_daemon/code/plugins/calibration/parameter_loader/error:unit_tests",
        "//score/config_management/config_daemon/code/plugins/calibration/service_toggler/details:unit_tests",
        "//score/config_management/config_daemon/code/plugins/calibration/services:unit_tests",
        "//score/config_management/config_daemon/code/plugins/calibration/factory/details:unit_tests",
    ],
    visibility = ["//score/config_management/config_daemon/code/plugins:__pkg__"],
)
