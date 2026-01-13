load("@score_baselibs//:bazel/unit_tests.bzl", "cc_unit_test_suites_for_host_and_qnx")

# Persistency library is a public interface for ConfigProvider users,
# which can be optionally used for enabling caching of parameter sets to persistency
# This in principle should enable faster access to already requested parameter sets.
# See README file of the ConfigProvider component on usage example.

cc_library(
    name = "persistency",
    srcs = [
        "persistency.cpp",
    ],
    hdrs = [
        "persistency.h",
    ],
    features = [
        "treat_warnings_as_errors",
        "additional_warnings",
        "strict_warnings",
    ],
    tags = ["FFI"],
    visibility = ["//score/config_management/config_provider/code:__subpackages__"],
    deps = [
        "@score_baselibs//score/filesystem",
        "//platform/aas/mw/diag",
        "//score/config_management/config_provider/code/parameter_set",
    ],
)

cc_library(
    name = "mock",
    testonly = True,
    hdrs = [
        "persistency_mock.h",
    ],
    features = [
        "treat_warnings_as_errors",
        "additional_warnings",
        "strict_warnings",
    ],
    visibility = [
        "//score/config_management/config_provider/code:__subpackages__",
    ],
    deps = [
        ":persistency",
        "@googletest//:gtest",
    ],
)

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    cc_unit_tests = [
        "//score/config_management/config_provider/code/persistency/details:unit_test",
        "//score/config_management/config_provider/code/persistency/error:unit_test",
    ],
    visibility = ["//score/config_management/config_provider:__subpackages__"],
)
