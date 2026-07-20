load("@rules_cc//cc:defs.bzl", "cc_library")
load("@score_baselibs//:bazel/unit_tests.bzl", "cc_gtest_unit_test", "cc_unit_test_suites_for_host_and_qnx")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

cc_library(
    name = "parameter_loader_impl",
    srcs = [
        "parameter_loader_impl.cpp",
    ],
    hdrs = [
        "parameter_loader_impl.h",
    ],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FFI"],
    visibility = [
        "//score/config_management/config_daemon/code/plugins/calibration:__subpackages__",
        "//score/config_management/config_daemon/code/plugins/calibration_loader:__subpackages__",
    ],
    deps = [
        "//platform/aas/mw/diag/dtc",
        "//score/config_management/config_daemon/code/fault_event_reporter",
        "//score/config_management/config_daemon/code/fault_event_reporter:fault_event_types",
        "//score/config_management/config_daemon/code/json_helper",
        "//score/config_management/config_daemon/code/plugins:plugin",
        "//score/config_management/config_daemon/code/plugins/calibration/parameter_loader",
        "//score/config_management/config_daemon/code/plugins/calibration/parameter_loader/error",
        "//score/config_management/config_daemon/code/plugins/coding/data",
        "//score/config_management/config_daemon/code/plugins/coding/error",
        "//score/config_management/config_daemon/code/plugins/coding/param_set_mapping",
        "//score/config_management/config_daemon/code/plugins/coding/types",
        "@score_baselibs//score/json",
        "@score_baselibs//score/json:json_impl",
        "@score_logging//score/mw/log",
    ],
)

cc_gtest_unit_test(
    name = "parameter_loader_impl_test",
    srcs = [
        "parameter_loader_impl_test.cpp",
    ],
    features = COMPILER_WARNING_FEATURES,
    visibility = ["//score/config_management/config_daemon:__subpackages__"],
    deps = [
        ":parameter_loader_impl",
        "//platform/aas/mw/diag/dtc:mock",
        "//score/config_management/config_daemon/code/data_model:parameterset_collection_mock",
        "//score/config_management/config_daemon/code/fault_event_reporter:fault_event_types",
        "//score/config_management/config_daemon/code/fault_event_reporter:mock",
        "//score/config_management/config_daemon/code/plugins/coding/param_set_mapping:mock",
        "@score_baselibs//score/json:json_impl",
        "@score_baselibs//score/json:mock",
    ],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [
        ":parameter_loader_impl_test",
    ],
    visibility = ["//score/config_management/config_daemon/code/plugins/calibration:__pkg__"],
)
