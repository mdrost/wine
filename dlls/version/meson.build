dlls_version_lib = shared_library('winapi-version', [
        'version.c',
    ],
    dependencies: [
        include_dep,
        libs_wine_dep,
        #dlls_winecrt0_dep,
        dlls_ntdll_dep,
        dlls_kernel32_dep,
    ]
)

dlls_version_dep = declare_dependency(
    link_with: dlls_version_lib,
)
