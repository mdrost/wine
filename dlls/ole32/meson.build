idl_files = [
        'dcom.idl',
        'irot.idl',
        'ole32_objidl.idl',
        'ole32_oleidl.idl',
        'ole32_unknwn.idl',
]

ole32_files = []
foreach idl_file : idl_files
    ole32_files += custom_target(idl_file,
        input: idl_file,
        output: '@BASENAME@.h',
        command: [
            'tools/widl/widl',
            '-I.', '-Iinclude',
            '-I../include',
            '-o', '@OUTPUT@',
            '@INPUT@',
        ],
        depends: [
            tools_widl_exe,
        ],
    )
endforeach

dlls_ole32_lib = shared_library('ole32', [
        'antimoniker.c',
        'bindctx.c',
        'classmoniker.c',
        'clipboard.c',
        'comcat.c',
        'compobj.c',
        'compositemoniker.c',
        'datacache.c',
        'defaulthandler.c',
        'dictionary.c',
        'enumx.c',
        'errorinfo.c',
        'filelockbytes.c',
        'filemoniker.c',
        'ftmarshal.c',
        'git.c',
        #'hglobalstream.c',
        #'ifs.c',
        'itemmoniker.c',
        'marshal.c',
        #'memlockbytes.c',
        'moniker.c',
        'ole2.c',
        'ole2impl.c',
        'ole2stubs.c',
        'ole32_main.c',
        'oleobj.c',
        'oleproxy.c',
        'pointermoniker.c',
        'rpc.c',
        'stg_prop.c',
        'stg_stream.c',
        'storage32.c',
        'stubmanager.c',
        #'usrmarshal.c',
    ],
    c_args: [
        '-D_OLE32_',
    ],
    link_args: [
        '-Wl,--warn-unresolved-symbols',
    ],
    include_directories: [
        include_directories('.'),
    ],
    dependencies: [
        include_dep,
        libs_wine_dep,
        dlls_winecrt0_dep,
        dlls_ntdll_dep,
        dlls_kernel32_dep,
        dlls_advapi32_dep,
        dlls_gdi32_dep,
        dlls_user32_dep,
        dlls_uuid_dep,
        dlls_rpcrt4_dep,
        declare_dependency(sources: ole32_files),
    ]
)

dlls_ole32_dep = declare_dependency(
    link_with: dlls_ole32_lib,
)
