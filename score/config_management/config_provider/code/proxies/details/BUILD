load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("@score_baselibs//score/language/safecpp:toolchain_features.bzl", "COMPILER_WARNING_FEATURES")

# MW COM proxy implementation (always exported to open-source)
cc_library(
    name = "details_mw_com",
    srcs = ["internal_config_provider_impl.cpp"],
    hdrs = ["internal_config_provider_impl.h"],
    features = COMPILER_WARNING_FEATURES,
    tags = ["FUSA"],
    visibility = [
        "//score/config_management/config_provider:__subpackages__",
    ],
    deps = [
        "//score/config_management/config_provider/code/config_provider/factory:buffer_size_report",
        "//score/config_management/config_provider/code/proxies:internal_config_provider",
        "//score/config_management/lib/mw_com_types:internal_config_provider_type",
        "@score_baselibs//score/concurrency:condition_variable",
        "@score_baselibs//score/concurrency/future",
        "@score_baselibs//score/json",
        "@score_baselibs//score/json:json_parser",
        "@score_logging//score/mw/log",
    ],
)

filegroup(
    name = "test_mw_com_config",
    testonly = True,
    srcs = ["test_mw_com_config.json"],
    visibility = ["//score/config_management/config_provider:__subpackages__"],
)

genrule(
    name = "test_mw_com_config_json_header",
    testonly = True,
    srcs = [":test_mw_com_config"],
    outs = ["test_mw_com_config_json.h"],
    cmd = """G=$$(printf %s "$@" | sed 's#^.*/bin/##' | tr -c 'A-Za-z0-9' '_' | tr 'a-z' 'A-Z')
{
    echo "#ifndef $$G"
    echo "#define $$G"
    echo 'constexpr char kTestMwComConfigJson[] = R"JSON('
    cat $(SRCS)
    echo ')JSON";'
    echo "#endif  // $$G"
} > $@""",
)

cc_library(
    name = "test_mw_com_config_json",
    testonly = True,
    hdrs = [":test_mw_com_config_json_header"],
    visibility = ["//score/config_management/config_provider:__subpackages__"],
)

# MW COM unit test
cc_test(
    name = "unit_test_mw",
    srcs = ["internal_config_provider_impl_test.cpp"],
    features = COMPILER_WARNING_FEATURES,
    tags = [
        "exclusive",  # Sandboxing is not properly working with LoLa message passing 2.0 (Ticket-217341)
        "unit",
    ],
    visibility = ["//score/config_management/config_provider/code/proxies:__pkg__"],
    deps = [
        ":details_mw_com",
        ":test_mw_com_config_json",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
        "@score_baselibs//score/concurrency:notification",
    ],
)
