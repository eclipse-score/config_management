# Use this macro for loading internal targets.
# The `custom.bzl` files are not imported from the open-source repository.
# Therefore, targets defined here are not affected between syncs.
def load_custom_targets(name = "custom_targets"):
    pass

def load_custom_test_suites():
    return []
