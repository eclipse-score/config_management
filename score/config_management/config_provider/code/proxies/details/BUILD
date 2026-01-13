[
    cc_library(
        name = "internal_config_provider_impl" + name,
        testonly = test_only,
        srcs = srcs,
        hdrs = hdrs,
        features = [
            "treat_warnings_as_errors",
            "additional_warnings",
            "strict_warnings",
        ],
        tags = ["FUSA"],
        visibility = [
            "@score_config_management//score/config_management/config_daemon/test/xpad_ara_com_mock:__subpackages__",
            "//score/config_management/config_provider:__subpackages__",
        ],
        deps = [
            "@score_baselibs//score/concurrency:condition_variable",
            "@score_baselibs//score/concurrency/future",
            "@score_baselibs//score/json",
            "@score_baselibs//score/mw/log",
            "//score/config_management/config_provider/code/proxies:internal_config_provider",
        ] + dep,
    )
    for name, srcs, hdrs, test_only, dep in [
        (
            "_ara_com",
            ["internal_config_provider_impl_r20_11.cpp"],
            ["internal_config_provider_impl_r20_11.h"],
            False,
            [
                "@score_config_management//score/config_management/config_daemon/adaptive_model/binding:internal_config_provider_socal_r20_11",
            ],
        ),
        (
            "_mw_com",
            ["mw_com/internal_config_provider_impl.cpp"],
            ["mw_com/internal_config_provider_impl.h"],
            False,
            [
                "@score_config_management//score/config_management/config_daemon/code/services/details/mw_com/generated_service:internal_config_provider_type",
            ],
        ),
        (
            "_for_ara_com_unit_tests",
            ["internal_config_provider_impl_r20_11.cpp"],
            ["internal_config_provider_impl_r20_11.h"],
            True,
            [
                "@score_config_management//score/config_management/config_daemon/adaptive_model/binding:internal_config_provider_socal_r20_11_mock",
            ],
        ),
        (
            "_for_mw_com_unit_tests",
            ["mw_com/internal_config_provider_impl.cpp"],
            ["mw_com/internal_config_provider_impl.h"],
            False,
            [
                "@score_config_management//score/config_management/config_daemon/code/services/details/mw_com/generated_service:internal_config_provider_type",
            ],
        ),
    ]
]

cc_test(
    name = "unit_test_r20_11",
    srcs = [
        "internal_config_provider_impl_r20_11_test.cpp",
    ],
    features = [
        "treat_warnings_as_errors",
        "additional_warnings",
        "strict_warnings",
    ],
    tags = ["unit"],
    visibility = ["//score/config_management/config_provider/code/proxies:__pkg__"],
    deps = [
        ":internal_config_provider_impl_for_ara_com_unit_tests",
        "@score_baselibs//score/concurrency:notification",
        "@googletest//:gtest_main",
    ],
)

filegroup(
    name = "test_mw_com_config",
    srcs = ["mw_com/mw_com_config.json"],
    visibility = ["//score/config_management/config_provider:__subpackages__"],
)

cc_test(
    name = "unit_test_mw",
    srcs = [
        "mw_com/internal_config_provider_impl_test.cpp",
    ],
    data = [
        ":test_mw_com_config",
    ],
    features = [
        "treat_warnings_as_errors",
        "additional_warnings",
        "strict_warnings",
    ],
    tags = [
        "exclusive",  # Sandboxing is not properly working with LoLa message passing 2.0 (Ticket-217341)
        "unit",
    ],
    visibility = ["//score/config_management/config_provider/code/proxies:__pkg__"],
    deps = [
        ":internal_config_provider_impl_for_mw_com_unit_tests",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)
