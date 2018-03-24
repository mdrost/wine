oleaut32_idl_files = [
        'oleaut32_oaidl.idl',
        'oleaut32_ocidl.idl',
]

oleaut32_headers = []
foreach idl_file : oleaut32_idl_files
    oleaut32_headers += custom_target('oleaut32_' + idl_file,
        input: idl_file,
        output: '@BASENAME@.h',
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
endforeach

oleaut32_private_sources = []

oleaut32_private_sources += custom_target('oleaut32_dlldata',
    input: oleaut32_idl_files,
    output: 'dlldata.c',
    command: [
        'tools/widl/widl',
        '--dlldata-only',
        '-o', '@OUTPUT@',
        '@INPUT@',
    ],
    depends: [
        tools_widl_exe,
    ],
)

foreach idl_file : oleaut32_idl_files
    oleaut32_private_sources += custom_target('oleaut32_c_' + idl_file,
        input: idl_file,
        output: '@BASENAME@_p.c',
        command: [
            'tools/widl/widl',
            '-I.', '-Iinclude', '-I../include',
            '-D__WINESRC__', '-D_OLEAUT32_',
            '-o', '@OUTPUT@',
            '@INPUT@',
        ],
        depends: [
            tools_widl_exe,
        ],
    )
endforeach

dlls_oleaut32_lib = shared_library('oleaut32', [
        'connpt.c',
        'dispatch.c',
        'hash.c',
        'oleaut.c',
        'olefont.c',
        'olepicture.c',
        'olepropframe.c',
        'recinfo.c',
        'safearray.c',
        'tmarshal.c',
        'typelib.c',
        'usrmarshal.c',
        'varformat.c',
        'variant.c',
        'vartype.c',
        oleaut32_private_sources,
    ],
    include_directories: [
        include_directories('.'),
    ],
    c_args: [
        '-D_OLEAUT32_',
        '-DENTRY_PREFIX=OLEAUTPS_',
        '-DPROXY_DELEGATION',
        '-DWINE_REGISTER_DLL',
        '-DPROXY_CLSID=CLSID_PSFactoryBuffer',
    ],
    link_args: [
        '-Wl,--warn-unresolved-symbols',
    ],
    build_rpath: '$ORIGIN/../comctl32:$ORIGIN/../urlmon:$ORIGIN/../windowscodecs',
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
        dlls_ole32_dep,
        declare_dependency(sources: oleaut32_headers),
        m_dep,
    ]
)

run_target('patchelf_oleaut32',
    command: [
        patchelf_program,
        '--add-needed', 'libcomctl32.so',
        '--add-needed', 'liburlmon.so',
        '--add-needed', 'libwindowscodecs.so',
        dlls_oleaut32_lib.full_path(),
    ],
)

dlls_oleaut32_dep = declare_dependency(
    link_with: dlls_oleaut32_lib,
)
