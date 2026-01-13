COMMON_FEATURES = [
    "treat_warnings_as_errors",
    "strict_warnings",
    "additional_warnings",
]

[
    cc_library(
        name = "details_bmw_impl" + name,
        testonly = test_only,
        srcs = [
            "fault_event_reporter_bmw_impl.cpp",
        ],
        hdrs = [
            "fault_event_reporter_bmw_impl.h",
        ],
        features = COMMON_FEATURES,
        tags = ["FFI"],
        visibility = [
            "@score_config_management//score/config_management/config_daemon/code:__subpackages__",
        ],
        deps = [
            "@score_baselibs//score/mw/log",
            "@score_config_management//score/config_management/config_daemon/code/fault_event_reporter:fault_event_types",
            "@score_config_management//score/config_management/config_daemon/code/fault_event_reporter/factory",
            "@score_config_management//score/config_management/config_daemon/code/proxies/fault_event",
        ] + dependencies,
    )
    for name, dependencies, tags, test_only in [
        (
            "",
            [
            ],
            [
                "FFI",
            ],
            False,
        ),
        (
            "_for_test",
            [
                "@score_config_management//score/config_management/config_daemon/code/fault_event_reporter/factory:mock",
                "@score_config_management//score/config_management/config_daemon/code/proxies/fault_event:mocks",
            ],
            [],
            True,
        ),
    ]
]

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
        features = COMMON_FEATURES,
        tags = ["FFI"],
        visibility = [
            "@score_config_management//score/config_management/config_daemon/code:__subpackages__",
        ],
        deps = [
            "@score_config_management//score/config_management/config_daemon/code/fault_event_reporter",
            "@score_config_management//score/config_management/config_daemon/code/fault_event_reporter:fault_event_score_types",
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
        "@score_config_management//score/config_management/config_daemon:__subpackages__",
    ],
    deps = select({
        "@score_config_management//score/config_management/config_daemon/code:is_score_variant": [":details_score_impl_for_test"],
        "//conditions:default": [
            ":details_bmw_impl_for_test",
            "@googletest//:gtest_main",
        ],
    }),
)
