dlls_ntdll_def_file = custom_target('libntdll.def',
    input: 'ntdll/ntdll.spec',
    output: 'lib@BASENAME@.def',
    command: [
        'tools/winebuild/winebuild',
        '-o', '@OUTPUT@',
        '--export', '@INPUT@',
        '-w', '--def', '-m64',
    ],
    depends: [
        tools_winebuild_exe,
    ],
)

dlls_kernel32_def_file = custom_target('libkernel32.def',
    input: 'kernel32/kernel32.spec',
    output: 'lib@BASENAME@.def',
    command: [
        'tools/winebuild/winebuild',
        '-o', '@OUTPUT@',
        '--export', '@INPUT@',
        '-w', '--def', '-m64',
    ],
    depends: [
        tools_winebuild_exe,
    ],
)

dlls_user32_def_file = custom_target('libuser32.def',
    input: 'user32/user32.spec',
    output: 'lib@BASENAME@.def',
    command: [
        'tools/winebuild/winebuild',
        '-o', '@OUTPUT@',
        '--export', '@INPUT@',
        '-w', '--def', '-m64',
    ],
    depends: [
        tools_winebuild_exe,
    ],
)

dlls_rpcrt4_def_file = custom_target('librpcrt4.def',
    input: 'rpcrt4/rpcrt4.spec',
    output: 'lib@BASENAME@.def',
    command: [
        'tools/winebuild/winebuild',
        '-o', '@OUTPUT@',
        '--export', '@INPUT@',
        '-w', '--def', '-m64',
    ],
    depends: [
        tools_winebuild_exe,
    ],
)

m_dep = compiler.find_library('m', required: false)
dl_dep = compiler.find_library('dl')
gmodule_dep = dependency('gmodule-2.0')
threads_dep = dependency('threads')
gio_dep = dependency('gio-2.0', version: '>=2.26')
qt5_dep = dependency('qt5', modules: ['Core', 'Gui', 'Widgets'])

#subdir('fake')
subdir('winecrt0')
subdir('ntdll')
subdir('kernel32')
subdir('advapi32')
subdir('gdi32')
#subdir('version')
#subdir('iphlpapi')
subdir('uuid')
subdir('user32')
#subdir('ws2_32')
#subdir('rpcrt4')
subdir('usp10')
#subdir('imm32')
#subdir('mpr')
#subdir('shlwapi')
#subdir('userenv')
#subdir('ole32')
#subdir('oleaut32')
#subdir('shell32')
#subdir('wininet')
#subdir('setupapi')
#subdir('opengl32')
#subdir('wined3d')
#subdir('dxgi')
#subdir('d3d10')
#subdir('d3d11')
#subdir('d3dx11_43')

subdir('dxguid')
subdir('d3dcompiler_43')
subdir('d3dcompiler_46')
subdir('d3dcompiler_47')

subdir('ntdll/tests')
subdir('kernel32/tests')
subdir('advapi32/tests')
subdir('gdi32/tests')
