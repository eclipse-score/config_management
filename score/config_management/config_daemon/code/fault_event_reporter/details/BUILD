COMMON_FEATURES = [
    "treat_warnings_as_errors",
    "strict_warnings",
    "additional_warnings",
]

[
    cc_library(
        name = "details_score_impl" + name,
        srcs = [
            "fault_event_reporter_score_impl.cpp",
        ],
        hdrs = [
            "fault_event_reporter_score_impl.h",
        ],
        features = COMMON_FEATURES,
        tags = ["FFI"],
        visibility = [
            "@score-config_management//score/config_management/config_daemon/code:__subpackages__",
        ],
        deps = [
            "@score-config_management//score/config_management/config_daemon/code/fault_event_reporter",
            "@score-config_management//score/config_management/config_daemon/code/fault_event_reporter:fault_event_score_types",
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
    name = "unit_test",
    srcs = ["fault_event_reporter_score_impl_test.cpp"],
    features = [
        "treat_warnings_as_errors",
        "strict_warnings",
        "additional_warnings",
    ],
    tags = ["unit"],
    visibility = [
        "@score-config_management//score/config_management/config_daemon:__subpackages__",
    ],
    deps = [":details_score_impl_for_test"],
)
