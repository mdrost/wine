dl_lib = compiler.find_library('dl')

libs_wine_lib = shared_library('wine', [
        'casemap.c',
        'collation.c',
        'config.c',
        'debug.c',
        'error.c',
        'ldt.c',
        'loader.c',
        'mmap.c',
        'port.c',
        'sortkey.c',
        'string.c',
        'version.c',
        'wctype.c',
    ],
    c_args: [
        '-DLIB_TO_BINDIR="/"',
        '-DLIB_TO_DLLDIR="/"',
        '-DBIN_TO_DLLDIR="/"',
        '-DBIN_TO_DATADIR="/"',
        '-DDLLDIR="/"',
        '-DBINDIR="/"',
    ],
    dependencies: [
        base_include_dep,
        libs_wine_port_dep,
        dl_lib,
    ],
)

libs_wine_dep = declare_dependency(
    link_with: libs_wine_lib,
)