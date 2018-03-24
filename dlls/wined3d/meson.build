opengl_dep = dependency('GL')

dlls_wined3d_lib = shared_library('wined3d', [
        'arb_program_shader.c',
        'ati_fragment_shader.c',
        'buffer.c',
        'context.c',
        'cs.c',
        'device.c',
        'directx.c',
        'drawprim.c',
        'gl_compat.c',
        'glsl_shader.c',
        'nvidia_texture_shader.c',
        'palette.c',
        'query.c',
        'resource.c',
        'sampler.c',
        'shader_sm1.c',
        'shader_sm4.c',
        'shader.c',
        'state.c',
        'stateblock.c',
        'surface.c',
        'swapchain.c',
        'texture.c',
        'utils.c',
        'vertexdeclaration.c',
        'view.c',
        'wined3d_main.c',
    ],
    dependencies: [
        include_dep,
        libs_wine_dep,
        #dlls_kernel32_dep,
        #dlls_opengl32_dep,
        #dlls_user32_dep,
        #dlls_gdi32_dep,
        #dlls_advapi32_dep,
        #dlls_opengl32_dep,
        opengl_dep,
    ]
)

dlls_wined3d_dep = declare_dependency(
    link_with: dlls_wined3d_lib,
)
