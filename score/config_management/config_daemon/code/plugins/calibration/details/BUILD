load("@rules_cc//cc:defs.bzl", "cc_library")
load("@score_baselibs//:bazel/unit_tests.bzl", "cc_gtest_unit_test")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

[
    cc_library(
        name = "calibration_impl" + name,
        testonly = test_only,
        srcs = [
            "calibration_impl.cpp",
        ],
        hdrs = [
            "calibration_impl.h",
        ],
        features = COMPILER_WARNING_FEATURES,
        tags = tags,
        visibility = ["//score/config_management/config_daemon/code:__subpackages__"],
        deps = [
            "//score/config_management/config_daemon/code/data_model:parameterset_collection",
            "//score/config_management/config_daemon/code/json_helper",
            "//score/config_management/config_daemon/code/plugins:plugin",
            "//score/config_management/config_daemon/code/plugins/calibration/error",
            "//score/config_management/config_daemon/code/plugins/calibration/parameter_loader/details:parameter_loader_impl",
            "//score/config_management/config_daemon/code/plugins/coding/data",
            "//score/config_management/config_daemon/code/plugins/coding/param_set_mapping",
            "//score/config_management/config_daemon/code/proxies/secure_debug:secure_debug_interface",
            "//score/config_management/config_daemon/code/types/initial_qualifier_state",
            "@score_baselibs//score/json",
            "@score_baselibs//score/json:json_impl",
            "@score_baselibs//score/language/safecpp/scoped_function:move_only_scoped_function",
            "@score_communication//score/mw/service",
            "@score_logging//score/mw/log",
        ] + dep,
    )
    for name, dep, tags, test_only in [
        (
            "",
            [
                "//score/config_management/config_daemon/code/plugins/calibration/service_toggler/details:service_toggler_impl",
                "//score/config_management/config_daemon/code/plugins/calibration/factory:factory_interface",
            ],
            [
                "FUSA",
            ],
            False,
        ),
        (
            "_for_test",
            [
                "//score/config_management/config_daemon/code/plugins/calibration/service_toggler:service_toggler_mock",
                "//score/config_management/config_daemon/code/plugins/calibration/factory:factory_mock",
                "//score/config_management/config_daemon/code/proxies/secure_debug:secure_debug_test",
                "//score/config_management/config_daemon/code/plugins/calibration/factory/details:factory_impl_test",
            ],
            [],
            True,
        ),
    ]
]

cc_gtest_unit_test(
    name = "calibration_test",
    srcs = [
        "calibration_impl_test.cpp",
    ],
    features = COMPILER_WARNING_FEATURES,
    visibility = ["//score/config_management/config_daemon:__subpackages__"],
    deps = [
        ":calibration_impl_for_test",
        "//score/config_management/config_daemon/code/data_model:parameterset_collection_manager_mock",
        "//score/config_management/config_daemon/code/plugins/calibration/parameter_loader:parameter_loader_mock",
        "//score/config_management/config_daemon/code/plugins/coding/data",
        "//score/config_management/config_daemon/code/plugins/coding/error",
        "//score/config_management/config_daemon/code/plugins/coding/param_set_mapping:mock",
        "//score/config_management/config_daemon/code/plugins/runtime_calibration/calibration_update_observer:mock",
        "//score/config_management/config_daemon/code/proxies/error",
        "//score/config_management/config_daemon/code/proxies/secure_debug:secure_debug_mock",
        "@score_baselibs//score/mw/log:recorder_mock",
        "@score_communication//score/mw/service:factory",
        "@score_communication//score/mw/service/ara:ara_test",
    ],
)
