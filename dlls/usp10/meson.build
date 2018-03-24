dlls_usp10_lib = shared_library('winapi-usp10', [
        'bidi.c',
        'bracket.c',
        'breaking.c',
        'indic.c',
        'indicsyllable.c',
        'linebreak.c',
        'mirror.c',
        'opentype.c',
        'shape.c',
        'shaping.c',
        'usp10.c',
    ],
    dependencies: [
        include_dep,
        libs_wine_dep,
        dlls_winecrt0_dep,
        #dlls_ntdll_dep,
        dlls_kernel32_dep,
        #dlls_advapi32_dep,
        dlls_gdi32_dep,
        dlls_user32_dep,
    ],
    install: true,
)

dlls_usp10_dep = declare_dependency(
    link_with: dlls_usp10_lib,
)
