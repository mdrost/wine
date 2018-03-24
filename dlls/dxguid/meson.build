dlls_dxguid_lib = static_library('winapi-dxguid', [
        'dx10guid.c',
        'dx8guid.c',
        'dx9guid.c',
        'dxguid.c',
    ],
    dependencies: [
        include_dep,
    ],
)

dlls_dxguid_dep = declare_dependency(
    link_with: dlls_dxguid_lib,
)
