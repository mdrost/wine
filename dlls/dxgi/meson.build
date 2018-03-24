dlls_dxgi_lib = shared_library('dxgi', [
        'adapter.c',
        'device.c',
        'dxgi_main.c',
        'factory.c',
        'output.c',
        'surface.c',
        'swapchain.c',
        'utils.c',
    ],
    dependencies: [
        include_dep,
        libs_wine_dep,
        dlls_kernel32_dep,
        dlls_wined3d_dep,
    ]
)

dlls_dxgi_dep = declare_dependency(
    link_with: dlls_dxgi_lib,
)
