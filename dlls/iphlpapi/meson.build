dlls_iphlpapi_lib = shared_library('iphlpapi', [
        'icmp.c',
        'ifenum.c',
        'iphlpapi_main.c',
        'ipstats.c',
    ],
    dependencies: [
        include_dep,
        libs_wine_dep,
        #dlls_winecrt0_dep,
        dlls_ntdll_dep,
        dlls_kernel32_dep,
        dlls_advapi32_dep,
    ]
)

dlls_iphlpapi_dep = declare_dependency(
    link_with: dlls_iphlpapi_lib,
)
