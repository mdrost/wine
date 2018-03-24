dlls_d3d11_lib = shared_library('d3d11', [
        'async.c',
        'buffer.c',
        'd3d11_main.c',
        'device.c',
        'inputlayout.c',
        'shader.c',
        'state.c',
        'texture.c',
        'utils.c',
        'view.c',
    ],
    dependencies: [
        include_dep,
        libs_wine_dep,
        dlls_kernel32_dep,
        dlls_d3d10_dep,
    ]
)

dlls_d3d11_dep = declare_dependency(
    link_with: dlls_d3d11_lib,
)
