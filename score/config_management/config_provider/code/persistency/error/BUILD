cc_library(
    name = "error",
    srcs = [
        "persistency_error.cpp",
    ],
    hdrs = [
        "persistency_error.h",
    ],
    features = [
        "treat_warnings_as_errors",
        "strict_warnings",
        "additional_warnings",
    ],
    tags = ["FFI"],
    visibility = ["//score/config_management/config_provider/code:__subpackages__"],
    deps = [
        "@score_baselibs//score/result",
    ],
)

cc_test(
    name = "unit_test",
    srcs = [
        "persistency_error_test.cpp",
    ],
    features = [
        "treat_warnings_as_errors",
        "strict_warnings",
        "additional_warnings",
    ],
    tags = ["unit"],
    visibility = ["//score/config_management/config_provider/code/persistency:__pkg__"],
    deps = [
        ":error",
        "//platform/aas/mw/log:fake",
        "@googletest//:gtest_main",
    ],
)
