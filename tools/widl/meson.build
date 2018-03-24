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

lfiles = lgen.process('parser.l')
pfiles = pgen.process('parser.y')

tools_widl_exe = executable('widl', [
        'client.c',
        'expr.c',
        'hash.c',
        'header.c',
        'proxy.c',
        'register.c',
        'server.c',
        'typegen.c',
        'typelib.c',
        'typetree.c',
        'utils.c',
        'widl.c',
        'write_msft.c',
    ], lfiles, pfiles,
    dependencies: [
        base_include_dep,
        libs_wpp_dep,
    ],
)
