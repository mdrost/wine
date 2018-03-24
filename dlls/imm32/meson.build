dlls_imm32_lib = shared_library('imm32', [
        'imm.c',
    ],
    dependencies: [
        include_dep,
        libs_wine_dep,
        #dlls_winecrt0_dep,
        #dlls_ntdll_dep,
        dlls_kernel32_dep,
        dlls_advapi32_dep,
        #dlls_gdi32_dep,
        dlls_user32_dep,
    ]
)

dlls_imm32_dep = declare_dependency(
    link_with: dlls_imm32_lib,
)
