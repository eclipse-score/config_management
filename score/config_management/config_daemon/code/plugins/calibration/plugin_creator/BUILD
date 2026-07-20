load("@rules_cc//cc:defs.bzl", "cc_library")
load("@score_baselibs//:bazel/unit_tests.bzl", "cc_gtest_unit_test")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

[
    cc_library(
        name = name,
        testonly = testonly,
        srcs = [
            "calibration_plugin_creator_impl.cpp",
        ],
        hdrs = [
            "calibration_plugin_creator_impl.h",
        ],
        features = COMPILER_WARNING_FEATURES,
        tags = ["FUSA"],
        visibility = [
            "//score/config_management/config_daemon/code:__subpackages__",
        ],
        deps = [
            "//score/config_management/config_daemon/code/plugins:plugin",
            "//score/config_management/config_daemon/code/plugins:plugin_creator",
        ] + dependencies,
    )
    for name, testonly, dependencies in [
        (
            "calibration_plugin_creator",
            False,
            [
                "//score/config_management/config_daemon/code/plugins/calibration/details:calibration_impl",
                "//score/config_management/config_daemon/code/plugins/calibration/factory/details:factory_impl",
            ],
        ),
        (
            "calibration_plugin_creator_for_unit_test",
            True,
            [
                "//score/config_management/config_daemon/code/plugins/calibration/details:calibration_impl_for_test",
                "//score/config_management/config_daemon/code/plugins/calibration/factory/details:factory_impl_for_test",
            ],
        ),
    ]
]

cc_gtest_unit_test(
    name = "unit_test",
    testonly = True,
    srcs = [
        "calibration_plugin_creator_test.cpp",
    ],
    features = COMPILER_WARNING_FEATURES,
    visibility = ["//score/config_management/config_daemon:__subpackages__"],
    deps = [
        ":calibration_plugin_creator_for_unit_test",
        "@score_logging//score/mw/log/test/console_logging_environment",
    ],
)
