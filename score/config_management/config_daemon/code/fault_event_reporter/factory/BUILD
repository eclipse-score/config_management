load("@rules_cc//cc:defs.bzl", "cc_library")

[
    cc_library(
        name = "factory" + name,
        testonly = testonly,
        hdrs = ["factory.h"],
        features = [
            "treat_warnings_as_errors",
            "additional_warnings",
            "strict_warnings",
        ],
        tags = ["FFI"],
        visibility = [
            "@score_config_management//score/config_management/config_daemon/code:__subpackages__",
        ],
        deps = select({
            "@score_config_management//score/config_management/config_daemon/code:is_score_variant": [
            ],
            "//conditions:default": [
                "@score_logging//score/mw/log",
                "@score_communication//score/mw/service:factory",
                "@score_config_management//score/config_management/config_daemon/code/fault_event_reporter",
                "@score_config_management//score/config_management/config_daemon/code/proxies/fault_event",
            ],
        }) + dependencies,
    )
    for name, testonly, dependencies in [
        (
            "",
            False,
            [
            ],
        ),
        (
            "_for_unit_test",
            True,
            select({
                "@score_config_management//score/config_management/config_daemon/code:is_score_variant": [
                ],
                "//conditions:default": [
                    "//platform/aas/mw/per/mock",
                ],
            }),
        ),
    ]
]

cc_library(
    name = "mock",
    testonly = True,
    srcs = [
        "factory_mock.cpp",
    ],
    hdrs = [
        "factory_mock.h",
    ],
    features = [
        "treat_warnings_as_errors",
        "additional_warnings",
        "strict_warnings",
    ],
    visibility = [
        "@score_config_management//score/config_management/config_daemon/code:__subpackages__",
    ],
    deps = [
        ":factory",
        "@googletest//:gtest",
    ],
)
