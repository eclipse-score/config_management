load("@rules_cc//cc:defs.bzl", "cc_library")
load("@score_baselibs//:bazel/unit_tests.bzl", "cc_gtest_unit_test")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

[
    cc_library(
        name = "details" + name,
        testonly = test_only,
        srcs = [
            "persistency_impl.cpp",
        ],
        hdrs = [
            "persistency_impl.h",
        ],
        features = COMPILER_WARNING_FEATURES,
        tags = ["FFI"],
        visibility = [
            "//score/config_management/config_provider/code:__subpackages__",
        ],
        deps = [
            "//score/config_management/config_provider/code/persistency",
            "//score/config_management/config_provider/code/persistency/error",
            "@score_logging//score/mw/log",
        ] + dep,
    )
    for name, test_only, dep in [
        (
            "",
            False,
            [
                # Target for storage impl
            ],
        ),
        (
            "_for_unit_test",
            True,
            [
                # Target for storage mock
            ],
        ),
    ]
]

cc_gtest_unit_test(
    name = "unit_test",
    srcs = [
        "persistency_impl_test.cpp",
    ],
    features = COMPILER_WARNING_FEATURES,
    visibility = [
        "//score/config_management/config_provider/code/persistency:__pkg__",
    ],
    deps = [
        ":details",
        ":details_for_unit_test",
        "@score_baselibs//score/filesystem:mock",
        "@score_logging//score/mw/log/test/console_logging_environment",
    ],
)
