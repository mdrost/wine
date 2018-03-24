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
        '--name-prefix=@BASENAME@_',
        #'-Dapi.prefix={@BASENAME@_}',
    ]
)

lfiles = lgen.process('ppl.l')
pfiles = pgen.process('ppy.y')

libs_wpp_lib = static_library('wpp', [
        'preproc.c',
        'wpp.c',
        lfiles,
        pfiles,
    ],
    dependencies: [
        base_include_dep,
    ],
)

libs_wpp_dep = declare_dependency(
    link_with: libs_wpp_lib,
)
