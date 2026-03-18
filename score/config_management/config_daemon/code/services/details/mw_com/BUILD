load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

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
        features = COMPILER_WARNING_FEATURES,
        tags = ["FUSA"],
        visibility = ["//score/config_management/config_daemon/code:__subpackages__"],
        deps = [
            "//score/config_management/config_daemon/code/data_model/error",
            "//score/config_management/config_daemon/code/services",
            "//score/config_management/config_daemon/code/services/details/mw_com/generated_service:internal_config_provider_type",
        ] + dep,
    )
    for name, dep, test_only in [
        (
            "_impl",
            [
                "@score_baselibs//score/result",
                "@score_communication//score/mw/com",
                "//score/config_management/config_daemon/code/services:internal_config_provider_reactor",
                "//score/config_management/config_daemon/code/data_model/parameterset_collection_interfaces:read_only_parameterset_collection",
                "@score_logging//score/mw/log",
            ],
            False,
        ),
        (
            "_test",
            [
                "//score/config_management/config_daemon/code/services:internal_config_provider_reactor_mock",
                "//score/config_management/config_provider/code/parameter_set",
                "//score/config_management/config_daemon/code/data_model/parameterset_collection_interfaces:read_only_parameterset_collection",
            ],
            True,
        ),
    ]
]

filegroup(
    name = "mw_com_config",
    srcs = ["mw_com_config.json"],
    visibility = [
        "//score/config_management/config_daemon/code:__subpackages__",
        "//score/config_management/config_daemon/test:__subpackages__",
    ],
)

cc_test(
    name = "unit_test",
    srcs = [
        "internal_config_provider_service_impl_test.cpp",
    ],
    data = [":mw_com_config"],
    features = COMPILER_WARNING_FEATURES + [
        "aborts_upon_exception",
    ],
    tags = [
        "exclusive",  # Sandboxing is not properly working with LoLa message passing 2.0 (Ticket-217341)
        "mw_com",
        "unit",
    ],
    visibility = ["//score/config_management/config_daemon/code/services/details/mw_com:__pkg__"],
    deps = [
        ":details_mw_com_test",
        "@googletest//:gtest_main",
    ],
)
