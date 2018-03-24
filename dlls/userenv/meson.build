dlls_userenv_lib = shared_library('userenv', [
        'userenv_main.c',
    ],
    dependencies: [
        include_dep,
        libs_wine_dep,
        #dlls_winecrt0_dep,
        dlls_ntdll_dep,
        dlls_kernel32_dep,
        dlls_advapi32_dep,
    ]
)

dlls_userenv_dep = declare_dependency(
    link_with: dlls_userenv_lib,
)
