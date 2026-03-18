load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")
load(":custom.bzl", "load_custom_targets")

[
    cc_library(
        name = "details_score_impl" + name,
        testonly = test_only,
        srcs = [
            "fault_event_reporter_score_impl.cpp",
        ],
        hdrs = [
            "fault_event_reporter_score_impl.h",
        ],
        features = COMPILER_WARNING_FEATURES,
        tags = ["FFI"],
        visibility = [
            "//score/config_management/config_daemon/code:__subpackages__",
        ],
        deps = [
            "//score/config_management/config_daemon/code/fault_event_reporter",
            "//score/config_management/config_daemon/code/fault_event_reporter:fault_event_score_types",
        ] + dependencies,
    )
    for name, dependencies, test_only in [
        (
            "",
            [],
            False,
        ),
        (
            "_for_test",
            ["@googletest//:gtest_main"],
            True,
        ),
    ]
]

cc_test(
    name = "score_impl_unit_test",
    srcs = ["fault_event_reporter_score_impl_test.cpp"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["unit"],
    visibility = [
        "//score/config_management/config_daemon:__subpackages__",
    ],
    deps = [":details_score_impl_for_test"],
)

load_custom_targets()
