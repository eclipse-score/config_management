load(
    "@score_tooling//cpp/libclang:libclang_toolchain.bzl",
    "libclang_toolchain",
)

# ============================================================================
# libclang toolchain for the C++ parser used by score rules
# ============================================================================
libclang_toolchain(
    name = "score_config_management_libclang",
    # score_tooling 2.x API: the parser derives builtin include dirs and
    # config-site flags from the cc_toolchain instead of explicit attrs.
    cc_toolchain = "@llvm_toolchain//:cc-clang-x86_64-linux",
    libclang = "@llvm_toolchain_llvm//:lib/libclang.so",
)

toolchain(
    name = "score_config_management_libclang_toolchain",
    toolchain = ":score_config_management_libclang",
    toolchain_type = "@score_tooling//cpp/libclang:libclang_toolchain_type",
    visibility = ["//:__subpackages__"],
)
