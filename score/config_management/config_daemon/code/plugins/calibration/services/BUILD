load("@rules_cc//cc:defs.bzl", "cc_library")
load("@score_baselibs//:bazel/unit_tests.bzl", "cc_gtest_unit_test", "cc_unit_test_suites_for_host_and_qnx")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

[
    cc_library(
        name = name,
        testonly = test_only,
        srcs = [
            "config_calibration_service.cpp",
        ],
        hdrs = [
            "config_calibration_service.h",
        ],
        features = COMPILER_WARNING_FEATURES,
        tags = tags,
        visibility = [
            "//score/config_management/config_daemon/code:__subpackages__",
        ],
        deps = dep,
    )
    for name, dep, tags, test_only in [
        (
            "config_calibration_service",
            [
                ":config_calibration_service_reactor",
                "@score_logging//score/mw/log",
                "//score/config_management/config_daemon/adaptive_model/binding:config_calibration",
                "//score/config_management/config_daemon/code/plugins/calibration/services/error",
            ],
            [
                "FUSA",
            ],
            False,
        ),
        (
            "config_calibration_service_for_unit_test",
            [
                ":config_calibration_service_reactor_mock",
                "//score/config_management/config_daemon/adaptive_model/binding:config_calibration_mock",
                "//score/config_management/config_daemon/code/plugins/calibration/services/error",
                "//score/config_management/config_daemon/code/data_model:parameterset_collection_mock",
                "//score/config_management/config_daemon/code/services:mock",
            ],
            [],
            True,
        ),
    ]
]

cc_gtest_unit_test(
    name = "unit_test",
    srcs = [
        "config_calibration_service_test.cpp",
    ],
    features = COMPILER_WARNING_FEATURES,
    visibility = ["//score/config_management/config_daemon:__subpackages__"],
    deps = [
        ":config_calibration_service_for_unit_test",
        "//score/config_management/config_daemon/code/services:mock",
    ],
)

cc_library(
    name = "config_calibration_service_reactor",
    srcs = ["config_calibration_service_reactor.cpp"],
    hdrs = ["config_calibration_service_reactor.h"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FFI"],
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        "@score_logging//score/mw/log",
    ],
)

cc_library(
    name = "config_calibration_service_reactor_mock",
    testonly = True,
    srcs = ["config_calibration_service_reactor_mock.cpp"],
    hdrs = ["config_calibration_service_reactor_mock.h"],
    features = COMPILER_WARNING_FEATURES,
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        ":config_calibration_service_reactor",
        "@googletest//:gtest",
    ],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [
        ":unit_test",
        "//score/config_management/config_daemon/code/plugins/calibration/services/details:unit_test",
        "//score/config_management/config_daemon/code/plugins/calibration/services/error:unit_test",
    ],
    visibility = ["//score/config_management/config_daemon/code/plugins/calibration:__pkg__"],
)
