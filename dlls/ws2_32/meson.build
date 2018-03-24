spec_object = custom_target('ws2_32.spec.o',
    input: [
        'ws2_32.spec',
        dlls_ntdll_def_file,
        dlls_kernel32_def_file,
        dlls_user32_def_file,
    ],
    output: 'ws2_32.spec.o',
    command: ['tools/winebuild/winebuild',
        '--cc-cmd=gcc', '--ld-cmd=ld',
        '-fasynchronous-unwind-tables', '-m64',
        '-fPIC',
        '--dll', '-o', '@OUTPUT@',
        '-E', '@INPUT0@',
        #'-L../../dlls', '-L../../libs/wine',
        #'-diphlpapi',
        '-duser32',
        #'-rversion.res'
        #'--', 'async.o', 'socket.o',
        #'../../dlls/iphlpapi/libiphlpapi.def',
        #'dlls/user32/libuser32.def',
        '@INPUT1@',
        '@INPUT2@',
        '@INPUT3@',
        #'../../libs/port/libwine_port.a',
        #'../../dlls/winecrt0/libwinecrt0.a',
        #'../../dlls/kernel32/libkernel32.def',
        #'../../dlls/ntdll/libntdll.def',
    ],
    depends: [
        tools_winebuild_exe,
    ],
)

dlls_ws2_32_lib = shared_library('ws2_32', [
        'async.c',
        'socket.c',
        #spec_object,
    ],
    c_args: [
        '-DUSE_WS_PREFIX',
    ],
    link_args: [
        '-Wl,--defsym=closesocket=WS_closesocket',
        '-Wl,--defsym=ioctlsocket=WS_ioctlsocket',
        #'-Wl,--warn-unresolved-symbols',
    ],
    dependencies: [
        include_dep,
        libs_wine_dep,
        dlls_winecrt0_dep,
        dlls_ntdll_dep,
        dlls_kernel32_dep,
        dlls_iphlpapi_dep,
        dlls_user32_dep,
    ]
)

dlls_ws2_32_dep = declare_dependency(
    link_with: dlls_ws2_32_lib,
)
