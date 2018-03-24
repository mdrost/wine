idl_files = [
    #'dcetypes.idl',
    #'epm.idl',
    #'irot.idl',
    #'itss.idl',
    #'schrpc.idl',
    #'svcctl.idl',
    'winedxgi.idl',
]

include_wine_files = []
foreach idl_file : idl_files
    include_wine_files += custom_target(idl_file,
        input: idl_file,
        output: '@BASENAME@.h',
        command: ['tools/widl/widl', '-m64', '-I.', '-Iinclude', '-I../include', '-o', '@OUTPUT@', '@INPUT@'],
        depends: [
            tools_widl_exe,
        ],
    )
endforeach