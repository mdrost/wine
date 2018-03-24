dlls_mpr_lib = shared_library('mpr', [
        'auth.c',
        'mpr_main.c',
        'multinet.c',
        'nps.c',
        'pwcache.c',
        'wnet.c',
    ],
    dependencies: [
        include_dep,
        libs_wine_dep,
        #dlls_winecrt0_dep,
        #dlls_ntdll_dep,
        dlls_kernel32_dep,
        dlls_advapi32_dep,
        dlls_user32_dep,
    ]
)

dlls_mpr_dep = declare_dependency(
    link_with: dlls_mpr_lib,
)
