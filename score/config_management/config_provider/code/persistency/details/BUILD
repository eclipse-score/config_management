load("@score_baselibs//:bazel/unit_tests.bzl", "cc_gtest_unit_test")

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
        features = [
            "treat_warnings_as_errors",
            "additional_warnings",
            "strict_warnings",
        ],
        tags = ["FFI"],
        visibility = [
            "//score/config_management/config_provider/code:__subpackages__",
        ],
        deps = [
            "@score_baselibs//score/mw/log",
            "//score/config_management/config_provider/code/persistency",
            "//score/config_management/config_provider/code/persistency/error",
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
    features = [
        "treat_warnings_as_errors",
        "strict_warnings",
        "additional_warnings",
    ],
    visibility = [
        "//score/config_management/config_provider/code/persistency:__pkg__",
    ],
    deps = [
        ":details_for_unit_test",
        ":persistency_empty",
        "@score_baselibs//score/filesystem:mock",
        #"@score_baselibs//score/mw/log/test/console_logging_environment",
    ],
)
