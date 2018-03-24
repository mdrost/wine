lgen = generator(flex,
    output: '@BASENAME@.yy.c',
    arguments: ['-o', '@OUTPUT@', '@INPUT@']
)

pgen = generator(bison,
    output: ['@BASENAME@.tab.c', '@BASENAME@.tab.h'],
    arguments: [
        '@INPUT@',
        '--defines',
        '--output=@OUTPUT0@',
        '-Dapi.prefix={@BASENAME@_}',
    ]
)

lfiles = lgen.process([
    '../d3dcompiler_43/asmshader.l',
    '../d3dcompiler_43/hlsl.l',
])
pfiles = pgen.process([
    '../d3dcompiler_43/asmshader.y',
    '../d3dcompiler_43/hlsl.y',
])

dlls_d3dcompiler_47_lib = shared_library('winapi-d3dcompiler_47', [
        '../d3dcompiler_43/asmparser.c',
        '../d3dcompiler_43/blob.c',
        '../d3dcompiler_43/bytecodewriter.c',
        '../d3dcompiler_43/compiler.c',
        #'../d3dcompiler_43/main.c',
        '../d3dcompiler_43/reflection.c',
        '../d3dcompiler_43/utils.c',
    ], lfiles, pfiles,
    include_directories: [
        include_directories('../d3dcompiler_43'),
    ],
    c_args: [
        '-DD3D_COMPILER_VERSION=47',
    ],
    dependencies: [
        base_include_dep,
        libs_wine_dep,
        libs_wpp_dep,
        dlls_winecrt0_dep,
        dlls_kernel32_dep,
        dlls_uuid_dep,
        dlls_dxguid_dep,
    ],
    install: true,
)

dlls_d3dcompiler_47_dep = declare_dependency(
    link_with: dlls_d3dcompiler_47_lib,
)
