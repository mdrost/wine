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
    'asmshader.l',
    'hlsl.l',
])
pfiles = pgen.process([
    'asmshader.y',
    'hlsl.y',
])

dlls_d3dcompiler_43_lib = shared_library('winapi-d3dcompiler_43', [
        'asmparser.c',
        'blob.c',
        'bytecodewriter.c',
        'compiler.c',
        #'main.c',
        'reflection.c',
        'utils.c',
    ], lfiles, pfiles,
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

dlls_d3dcompiler_43_dep = declare_dependency(
    link_with: dlls_d3dcompiler_43_lib,
)
