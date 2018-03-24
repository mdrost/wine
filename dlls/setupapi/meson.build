dlls_setupapi_lib = shared_library('setupapi', [
        'devinst.c',
        'dialog.c',
        'dirid.c',
        'diskspace.c',
        'fakedll.c',
        'install.c',
        'misc.c',
        'parser.c',
        'query.c',
        'queue.c',
        'setupcab.c',
        'stringtable.c',
        'stubs.c',
    ],
    c_args: [
        '-D_SETUPAPI_',
    ],
    link_args: [
        #'-Wl,--warn-unresolved-symbols',
    ],
    dependencies: [
        include_dep,
        libs_wine_dep,
        #dlls_winecrt0_dep,
        dlls_ntdll_dep,
        dlls_kernel32_dep,
        dlls_advapi32_dep,
        dlls_user32_dep,
        dlls_version_dep,
        dlls_uuid_dep,
        dlls_rpcrt4_dep,
    ],
)

dlls_setupapi_dep = declare_dependency(
    link_with: dlls_setupapi_lib,
)
