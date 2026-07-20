load("@rules_cc//cc:defs.bzl", "cc_library")
load("@score_baselibs//:bazel/unit_tests.bzl", "cc_gtest_unit_test", "cc_unit_test_suites_for_host_and_qnx")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

[
    cc_library(
        name = "factory_impl" + name,
        testonly = test_only,
        srcs = [
            "factory_impl.cpp",
        ],
        hdrs = [
            "factory_impl.h",
        ],
        features = COMPILER_WARNING_FEATURES,
        tags = tags,
        visibility = ["//score/config_management/config_daemon/code:__subpackages__"],
        deps = [
            "//score/config_management/config_daemon/code/plugins/calibration/factory:factory_interface",
            "@score_baselibs//score/json:json_impl",
            "@score_communication//score/mw/service:factory",
        ] + dep,
    )
    for name, dep, tags, test_only in [
        (
            "",
            [
                "//score/config_management/config_daemon/code/plugins/runtime_calibration/calibration_update_observer:calibration_update_observer",
                "//score/config_management/config_daemon/code/proxies/secure_debug:secure_debug",
                "//score/config_management/config_daemon/code/plugins/calibration/services:config_calibration_service",
                "//platform/aas/mw/diag/dtc/details:factory_impl",
                "@score_communication//score/mw/service/backend/ara",
                "//score/config_management/config_daemon/code/plugins/calibration/service_toggler/details:service_toggler_impl",
                "//score/config_management/config_daemon/code/plugins/calibration/services/details:config_calibration_service_reactor_impl",
                "//score/config_management/config_daemon/code/plugins/coding/param_set_mapping/details",
            ],
            [
                "FFI",
            ],
            False,
        ),
        (
            "_for_test",
            [
                "//score/config_management/config_daemon/code/fault_event_reporter:mock",
                "//score/config_management/config_daemon/code/fault_event_reporter:fault_event_types",
                "//score/config_management/config_daemon/code/proxies/secure_debug:secure_debug_test",
                "//score/config_management/config_daemon/code/plugins/runtime_calibration/calibration_update_observer:calibration_update_observer_for_test",
                "//score/config_management/config_daemon/code/plugins/calibration/services:config_calibration_service_for_unit_test",
                "//platform/aas/mw/diag/dtc/details:factory_impl_test",
                "@score_communication//score/mw/service/backend/ara:ara_test",
                "//score/config_management/config_daemon/code/plugins/runtime_calibration/calibration_update_observer:mock",
                "//score/config_management/config_daemon/code/services:mock",
                "//score/config_management/config_daemon/code/data_model:parameterset_collection_mock",
                "//score/config_management/config_daemon/code/plugins/coding/param_set_mapping:mock",
                "//score/config_management/config_daemon/code/plugins/calibration/services/details:config_calibration_service_reactor_impl",
                "//score/config_management/config_daemon/code/plugins/calibration/service_toggler/details:service_toggler_impl_for_unit_test",
            ],
            [],
            True,
        ),
    ]
]

cc_gtest_unit_test(
    name = "factory_impl_test",
    srcs = [
        "factory_impl_test.cpp",
    ],
    features = COMPILER_WARNING_FEATURES,
    visibility = ["//score/config_management/config_daemon:__subpackages__"],
    deps = [
        ":factory_impl_for_test",
        "@score_communication//score/mw/service",
    ],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [
        ":factory_impl_test",
    ],
    visibility = ["//score/config_management/config_daemon/code/plugins/calibration:__pkg__"],
)
