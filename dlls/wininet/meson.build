dlls_wininet_lib = shared_library('wininet', [
        'cookie.c',
        'dialogs.c',
        'ftp.c',
        'gopher.c',
        'http.c',
        'internet.c',
        'netconnection.c',
        'urlcache.c',
        'utility.c',
    ],
    c_args: [
        '-D_WINX32_',
    ],
    link_args: [
        '-Wl,--warn-unresolved-symbols',
    ],
    dependencies: [
        include_dep,
        libs_wine_dep,
        dlls_winecrt0_dep,
        dlls_ntdll_dep,
        dlls_kernel32_dep,
        dlls_advapi32_dep,
        dlls_user32_dep,
        dlls_ws2_32_dep,
        dlls_mpr_dep,
        dlls_shlwapi_dep,
        dlls_shell32_dep,
    ]
)

dlls_wininet_dep = declare_dependency(
    link_with: dlls_wininet_lib,
)
