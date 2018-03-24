dlls_d3d10_lib = shared_library('d3d10', [
        'd3d10_main.c',
        'effect.c',
        'shader.c',
        'stateblock.c',
        'utils.c',
    ],
    dependencies: [
        include_dep,
        libs_wine_dep,
        dlls_kernel32_dep,
        dlls_dxgi_dep,
    ]
)

dlls_d3d10_dep = declare_dependency(
    link_with: dlls_d3d10_lib,
)
