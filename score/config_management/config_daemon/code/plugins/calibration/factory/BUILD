load("@rules_cc//cc:defs.bzl", "cc_library")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

cc_library(
    name = "factory_interface",
    srcs = [
        "factory.cpp",
    ],
    hdrs = [
        "factory.h",
    ],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FFI"],
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        "//platform/aas/mw/diag/dtc",
        "//score/config_management/config_daemon/code/data_model:parameterset_collection",
        "//score/config_management/config_daemon/code/fault_event_reporter",
        "//score/config_management/config_daemon/code/plugins/calibration/parameter_loader/details:parameter_loader_impl",
        "//score/config_management/config_daemon/code/plugins/calibration/service_toggler:service_toggler_interface",
        "//score/config_management/config_daemon/code/plugins/coding/param_set_mapping/details",
        "//score/config_management/config_daemon/code/plugins/runtime_calibration/calibration_update_observer:interface",
        "//score/config_management/config_daemon/code/proxies/secure_debug:secure_debug_interface",
        "//score/config_management/config_daemon/code/services",
        "@score_communication//score/mw/service",
    ],
)

cc_library(
    name = "factory_mock",
    testonly = True,
    srcs = [
        "mock_factory.cpp",
    ],
    hdrs = [
        "mock_factory.h",
    ],
    features = COMPILER_WARNING_FEATURES,
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        ":factory_interface",
        "@googletest//:gtest",
    ],
)
