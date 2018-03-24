dlls_opengl32_lib = shared_library('opengl32', [
        'opengl_ext.c',
        'opengl_norm.c',
        'wgl.c',
    ],
    dependencies: [
        include_dep,
        libs_wine_dep,
        #dlls_kernel32_dep,
        #dlls_opengl32_dep,
        #dlls_user32_dep,
        #dlls_gdi32_dep,
        #dlls_advapi32_dep,
    ]
)

dlls_opengl32_dep = declare_dependency(
    link_with: dlls_opengl32_lib,
)
