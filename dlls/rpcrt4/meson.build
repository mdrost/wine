epm_file = custom_target('epm.h',
    input: 'epm.idl',
    output: 'epm.h',
    command: [
        'tools/widl/widl',
        '-I.', '-Iinclude', '-I../include',
        '-o', '@OUTPUT@',
        '@INPUT@',
    ],
    depends: [
        tools_widl_exe,
    ],
)

dlls_rpcrt4_lib = shared_library('rpcrt4', [
        'cproxy.c',
        'cpsf.c',
        'cstub.c',
        'ndr_clientserver.c',
        'ndr_contexthandle.c',
        'ndr_es.c',
        'ndr_fullpointer.c',
        'ndr_marshall.c',
        'ndr_ole.c',
        'ndr_stubless.c',
        'rpc_assoc.c',
        'rpc_async.c',
        'rpc_binding.c',
        'rpc_epmap.c',
        'rpc_message.c',
        'rpc_server.c',
        'rpc_transport.c',
        'rpcrt4_main.c',
    ],
    include_directories: [
        include_directories('.'),
    ],
    c_args: [
        '-D_RPCRT4_',
        '-DMSWMSG',
    ],
    link_args: [
        '-Wl,--warn-unresolved-symbols',
    ],
    build_rpath: '$ORIGIN/../iphlpapi:$ORIGIN/../user32:$ORIGIN/../ws2_32',
    dependencies: [
        declare_dependency(sources: epm_file),
        include_dep,
        libs_wine_dep,
        dlls_winecrt0_dep,
        dlls_ntdll_dep,
        dlls_kernel32_dep,
        dlls_advapi32_dep,
        dlls_iphlpapi_dep,
        dlls_uuid_dep,
        dlls_user32_dep,
        dlls_ws2_32_dep,
    ]
)

#run_target('patchelf_rpcrt4',
#    command: [
#        patchelf_program,
#        '--add-needed', 'libiphlpapi.so',
#        '--add-needed', 'libuser32.so',
#        '--add-needed', 'libws2_32.so',
#        dlls_rpcrt4_lib.full_path(),
#    ],
#)

dlls_rpcrt4_dep = declare_dependency(
    link_with: dlls_rpcrt4_lib,
)
