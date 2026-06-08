# Use this macro for loading internal targets.
# The `custom.bzl` files are not imported from the open-source repository.
# Therefore, targets defined here are not affected between syncs.
def load_custom_targets(name = "custom_targets"):
    # OSS stubs: the SOCAL r20_11 factory is an internal target not available in
    # the open-source build. We alias it to factory_mw_com so that the
    # ConfigProvider_r20_11 and ConfigProvider_r20_11_for_unit_tests aliases in
    # the parent BUILD file resolve without errors.
    native.alias(
        name = "factory_socal_r20_11",
        actual = ":factory_mw_com",
        visibility = ["//score/config_management/config_provider:__subpackages__"],
    )
    native.alias(
        name = "factory_socal_r20_11_for_unit_tests",
        actual = ":factory_mw_com",
        visibility = ["//score/config_management/config_provider:__subpackages__"],
    )

def load_custom_test_suites():
    return []
