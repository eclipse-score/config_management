load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")

COMMON_FEATURES = [
    "treat_warnings_as_errors",
    "strict_warnings",
    "additional_warnings",
    "strict_warnings_no_error",
]

[
    cc_library(
        name = "details_mw_com" + name,
        testonly = test_only,
        srcs = [
            "internal_config_provider_service_impl.cpp",
        ],
        hdrs = [
            "internal_config_provider_service_impl.h",
        ],
        features = COMMON_FEATURES,
        tags = ["FUSA"],
        visibility = ["@score_config_management//score/config_management/config_daemon/code:__subpackages__"],
        deps = [
            "@score_config_management//score/config_management/config_daemon/code/data_model/error",
            "@score_config_management//score/config_management/config_daemon/code/services",
            "@score_config_management//score/config_management/config_daemon/code/services/details/mw_com/generated_service:internal_config_provider_type",
        ] + dep,
    )
    for name, dep, test_only in [
        (
            "_impl",
            [
                "@score_baselibs//score/result",
                "@score_communication//score/mw/com",
                "@score_config_management//score/config_management/config_daemon/code/services:internal_config_provider_reactor",
                "@score_config_management//score/config_management/config_daemon/code/data_model/parameterset_collection_interfaces:read_only_parameterset_collection",
                "@score_logging//score/mw/log",
            ],
            False,
        ),
        (
            "_test",
            [
                "@score_config_management//score/config_management/config_daemon/code/services:internal_config_provider_reactor_mock",
                "//score/config_management/config_provider/code/parameter_set",
                "@score_config_management//score/config_management/config_daemon/code/data_model/parameterset_collection_interfaces:read_only_parameterset_collection",
            ],
            True,
        ),
    ]
]

filegroup(
    name = "test_mw_com_config",
    srcs = ["mw_com_config.json"],
)

cc_test(
    name = "unit_test",
    srcs = [
        "internal_config_provider_service_impl_test.cpp",
    ],
    data = [":test_mw_com_config"],
    features = COMMON_FEATURES + [
        "aborts_upon_exception",
    ],
    tags = [
        "exclusive",  # Sandboxing is not properly working with LoLa message passing 2.0 (Ticket-217341)
        "mw_com",
        "unit",
    ],
    visibility = ["@score_config_management//score/config_management/config_daemon/code/services/details/mw_com:__pkg__"],
    deps = [
        ":details_mw_com_test",
        "@googletest//:gtest_main",
    ],
)
