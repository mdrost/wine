dlls_shlwapi_lib = shared_library('shlwapi', [
        'assoc.c',
        'clist.c',
        'istream.c',
        'msgbox.c',
        'ordinal.c',
        'path.c',
        'reg.c',
        'regstream.c',
        'shlwapi_main.c',
        'stopwatch.c',
        'string.c',
        'thread.c',
        'url.c',
        'wsprintf.c',
    ],
    c_args: [
        '-D_SHLWAPI_',
    ],
    link_args: [
        '-Wl,--warn-unresolved-symbols',
    ],
    dependencies: [
        include_dep,
        libs_wine_dep,
        #dlls_winecrt0_dep,
        dlls_ntdll_dep,
        dlls_kernel32_dep,
        dlls_advapi32_dep,
        dlls_gdi32_dep,
        dlls_user32_dep,
        dlls_uuid_dep,
        dlls_version_dep,
        m_dep,
    ]
)

dlls_shlwapi_dep = declare_dependency(
    link_with: dlls_shlwapi_lib,
)
