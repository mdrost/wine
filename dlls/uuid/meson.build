dlls_uuid_lib = static_library('uuid', [
        'd2d.c',
        'uuid.c',
    ],
    dependencies: [
        include_dep,
    ],
)

dlls_uuid_dep = declare_dependency(
    link_with: dlls_uuid_lib,
)
