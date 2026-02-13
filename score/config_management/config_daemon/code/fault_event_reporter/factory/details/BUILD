load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")

COMMON_FEATURES = [
    "treat_warnings_as_errors",
    "strict_warnings",
    "additional_warnings",
]

[
    cc_library(
        name = "factory_impl" + name,
        testonly = test_only,
        srcs = ["factory_impl.cpp"],
        hdrs = ["factory_impl.h"],
        features = COMMON_FEATURES,
        tags = tags,
        visibility = ["@score_config_management//score/config_management/config_daemon/code:__subpackages__"],
        deps = [
            "@score_config_management//score/config_management/config_daemon/code/fault_event_reporter/factory",
        ] + dependencies,
    )
    for name, dependencies, tags, test_only in [
        (
            "",
            select({
                "@score_config_management//score/config_management/config_daemon/code:is_score_variant": [
                ],
                "//conditions:default": [
                    "@score_communication//score/mw/service:factory",
                    "@score_communication//score/mw/service/ara",
                    "@score_config_management//score/config_management/config_daemon/adaptive_model/binding:persistency",
                    "@score_config_management//score/config_management/config_daemon/code/proxies/fault_event/details:impl",
                ],
            }),
            [
                "FFI",
            ],
            False,
        ),
        (
            "_for_test",
            select({
                "@score_config_management//score/config_management/config_daemon/code:is_score_variant": [
                ],
                "//conditions:default": [
                    "//platform/aas/mw/per/mock",
                    "@score_communication//score/mw/service/mw:mw_test",
                    "@score_config_management//score/config_management/config_daemon/code/proxies/fault_event/details:for_unit_test",
                ],
            }),
            [],
            True,
        ),
    ]
]

cc_test(
    name = "unit_test",
    testonly = True,
    srcs = [
        "factory_impl_test.cpp",
    ],
    features = [
        "treat_warnings_as_errors",
        "additional_warnings",
        "strict_warnings",
    ],
    tags = ["unit"],
    visibility = [
        "@score_config_management//score/config_management/config_daemon:__subpackages__",
    ],
    deps = [
        ":factory_impl_for_test",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
        "@score_baselibs//score/language/futurecpp",
    ],
)
