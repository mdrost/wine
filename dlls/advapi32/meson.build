svcctl_files = custom_target('svcctl.h',
    input: [
        'svcctl.idl',
    ],
    output: '@BASENAME@.h',
    command: ['tools/widl/widl', '-m64', '-I.', '-Iinclude', '-I../include', '-o', '@OUTPUT@', '@INPUT@'],
    depends: [
        tools_widl_exe,
    ],
)

spec_object = custom_target('advapi32.spec.o',
    input: [
        'advapi32.spec',
        dlls_rpcrt4_def_file,
    ],
    output: 'advapi32.spec.o',
    command: ['tools/winebuild/winebuild',
        '--cc-cmd=gcc', '--ld-cmd=ld',
        '-fasynchronous-unwind-tables', '-m64',
        '-fPIC',
        '--dll', '-o', '@OUTPUT@',
        '-E', '@INPUT0@',
        '-drpcrt4',
        '@INPUT1@',
    ],
    depends: [
        tools_winebuild_exe,
    ],
)

dlls_advapi32_lib = shared_library('advapi32', [
        'advapi.c',
        'cred.c',
        'crypt.c',
        'crypt_arc4.c',
        'crypt_des.c',
        'crypt_lmhash.c',
        'crypt_md4.c',
        'crypt_md5.c',
        'crypt_sha.c',
        'eventlog.c',
        'lsa.c',
        'perf.c',
        'registry.c',
        'security.c',
        'service.c',
        'wmi.c',
        #spec_object,
    ],
    c_args: [
        '-D_ADVAPI32_',
    ],
    link_args: [
        #'-lrpcrt4',
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
        declare_dependency(sources: svcctl_files),
    ],
    link_with: [
        #dlls_rpcrt4_fake_lib,
    ],
    build_rpath: '$ORIGIN/../rpcrt4',
)

#run_command(patchelf_program, [
#    '--add-needed', 'librpcrt4.so',
#    dlls_advapi32_lib.full_path(),
#])
run_target('patchelf_advapi32',
    command: [
        patchelf_program,
        '--add-needed', 'librpcrt4.so',
        dlls_advapi32_lib.full_path(),
    ],
)
#dlls_patchelf_advapi32 = custom_target('patchelf_advapi32',
#    input: dlls_advapi32_lib,
#    output: [],
#    command: [
#        patchelf_program,
#        '--add-needed', 'librpcrt4.so',
#        dlls_advapi32_lib.full_path(),
#    ],
#)

dlls_advapi32_dep = declare_dependency(
    link_with: dlls_advapi32_lib,
    sources: [
        #dlls_patchelf_advapi32,
    ],
)
