load("@rules_cc//cc:defs.bzl", "cc_library")
load("@score_baselibs//:bazel/unit_tests.bzl", "cc_gtest_unit_test", "cc_unit_test_suites_for_host_and_qnx")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

[
    cc_library(
        name = name,
        testonly = test_only,
        srcs = [
            "service_toggler_impl.cpp",
        ],
        hdrs = [
            "service_toggler_impl.h",
        ],
        features = COMPILER_WARNING_FEATURES,
        tags = tags,
        visibility = [
            "//score/config_management/config_daemon/code:__subpackages__",
        ],
        deps = [
            "//score/config_management/config_daemon/code/plugins/calibration/service_toggler:service_toggler_interface",
            "@score_communication//score/mw/service",
        ] + dep,
    )
    for name, dep, tags, test_only in [
        (
            "service_toggler_impl",
            [
                "@score_logging//score/mw/log",
                "//score/config_management/config_daemon/code/data_model:parameterset_collection",
                "//score/config_management/config_daemon/code/services",
            ],
            [
                "FFI",
            ],
            False,
        ),
        (
            "service_toggler_impl_for_unit_test",
            [
                "//score/config_management/config_daemon/code/data_model:parameterset_collection_mock",
                "//score/config_management/config_daemon/code/services:mock",
            ],
            [],
            True,
        ),
    ]
]

cc_gtest_unit_test(
    name = "service_toggler_test",
    srcs = [
        "service_toggler_impl_test.cpp",
    ],
    features = COMPILER_WARNING_FEATURES,
    visibility = ["//score/config_management/config_daemon/code:__subpackages__"],
    deps = [
        ":service_toggler_impl",
        "//score/config_management/config_daemon/code/plugins/calibration/factory:factory_mock",
    ],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [
        ":service_toggler_test",
    ],
    visibility = ["//score/config_management/config_daemon/code/plugins/calibration:__pkg__"],
)
