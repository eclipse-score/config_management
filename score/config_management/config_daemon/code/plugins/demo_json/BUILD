load("@score_baselibs//:bazel/unit_tests.bzl", "cc_unit_test_suites_for_host_and_qnx")

cc_unit_test_suites_for_host_and_qnx(
    name = "unit_tests",
    test_suites_from_sub_packages = [
        "//score/config_management/config_daemon/code/plugins/demo_json/details:unit_tests",
        "//score/config_management/config_daemon/code/plugins/demo_json/parameter_loader/details:unit_tests",
        "//score/config_management/config_daemon/code/plugins/demo_json/plugin_creator:unit_tests",
    ],
    visibility = ["//score/config_management/config_daemon/code/plugins:__pkg__"],
)

filegroup(
    name = "demo_parameters",
    srcs = ["etc/demo_parameters.json"],
    visibility = ["//score/config_management/config_daemon/test:__subpackages__"],
)
