load(
    "@score_tooling//cpp/libclang:libclang_toolchain.bzl",
    "libclang_toolchain",
)

# ============================================================================
# libclang toolchain for the C++ parser used by score rules
# ============================================================================
libclang_toolchain(
    name = "score_config_management_libclang",
    cxx_builtin_include = "@llvm_toolchain_llvm//:cxx_builtin_include",
    extra_config_site = "@llvm_toolchain_llvm//:extra_config_site",
    libclang = "@llvm_toolchain_llvm//:lib/libclang.so",
)

toolchain(
    name = "score_config_management_libclang_toolchain",
    toolchain = ":score_config_management_libclang",
    toolchain_type = "@score_tooling//cpp/libclang:libclang_toolchain_type",
    visibility = ["//:__subpackages__"],
)
