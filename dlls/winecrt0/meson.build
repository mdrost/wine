dlls_winecrt0_lib = static_library('winapi-wincrt0', [
        'delay_load.c',
        'dll_entry.c',
        'dll_main.c',
        'drv_entry.c',
        #'exception.c',
        'exe16_entry.c',
        'exe_entry.c',
        'exe_main.c',
        'exe_wentry.c',
        'exe_wmain.c',
        'init.c',
        'register.c',
        #'stub.c',
    ],
    dependencies: [
        include_dep,
    ],
    install: true,
)

dlls_winecrt0_dep = declare_dependency(
    link_with: dlls_winecrt0_lib,
)
