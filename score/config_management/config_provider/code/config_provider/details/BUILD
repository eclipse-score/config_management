load("@score_baselibs//:bazel/unit_tests.bzl", "cc_unit_test_suites_for_host_and_qnx")

# Variables
COMMON_FEATURES = [
    "treat_warnings_as_errors",
    "strict_warnings",
    "additional_warnings",
]

cc_library(
    name = "details",
    srcs = [
        "config_provider_impl.cpp",
    ],
    hdrs = [
        "config_provider_impl.h",
    ],
    features = COMMON_FEATURES,
    tags = ["FUSA"],
    visibility = [
        "//score/config_management/config_provider:__subpackages__",
    ],
    deps = [
        "@score_baselibs//score/mw/log",
        "@score_communication//score/mw/service:proxy_future",
        "//score/config_management/config_provider/code/config_provider",
        "//score/config_management/config_provider/code/config_provider/error",
        "//score/config_management/config_provider/code/persistency",
        "//score/config_management/config_provider/code/proxies:internal_config_provider",
        "@score_baselibs//score/language/futurecpp",
    ],
)

cc_test(
    name = "unit_test",
    srcs = [
        "config_provider_impl_test.cpp",
    ],
    features = COMMON_FEATURES,
    tags = ["unit"],
    visibility = [
        "//score/config_management/config_provider:__subpackages__",
    ],
    deps = [
        ":details",
        "@score_baselibs//score/concurrency:notification",
        #"@score_baselibs//score/mw/log/test/console_logging_environment",
        "//score/config_management/config_provider/code/config_provider/error",
        "//score/config_management/config_provider/code/persistency:mock",
        "//score/config_management/config_provider/code/persistency/error",
        "//score/config_management/config_provider/code/proxies:mock",
    ],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [
        ":unit_test",
    ],
    visibility = ["//score/config_management/config_provider:__subpackages__"],
)
