project(
    'wine',
    ['c', 'cpp'],
    license : 'LGPLv2',
    default_options: [
        '-Dc_args=-O2'
    ],
)

add_global_arguments('-D__WINESRC__', language : 'c')
#add_global_arguments('-m64', language : 'c')
#add_global_arguments('-fPIC', language : 'c')
add_global_arguments('-fno-strict-aliasing', language : 'c')
add_global_arguments('-Wall', language : 'c')
add_global_arguments('-Wdeclaration-after-statement', language : 'c')
#add_global_arguments('-Wempty-body', language : 'c')
add_global_arguments('-Wignored-qualifiers', language : 'c')
#add_global_arguments('-Wno-packed-not-aligned', language : 'c')
add_global_arguments('-Wshift-overflow=2', language : 'c')
add_global_arguments('-Wstrict-prototypes', language : 'c')
add_global_arguments('-Wtype-limits', language : 'c')
add_global_arguments('-Wvla', language : 'c')
add_global_arguments('-Wwrite-strings', language : 'c')
add_global_arguments('-Wpointer-arith', language : 'c')
add_global_arguments('-Wlogical-op', language : 'c')
add_global_arguments('-Werror=implicit-function-declaration', language : 'c')
add_global_arguments('-Werror=incompatible-pointer-types', language : 'c')
#add_global_arguments('-Werror=deprecated-declarations', language : 'c')
#add_global_arguments('-Werror=int-conversion', language : 'c')
add_global_arguments('-Werror=format', language : 'c')
add_global_arguments('-g', language : 'c')
add_global_arguments('-gdwarf-2', language : 'c')
add_global_arguments('-gstrict-dwarf', language : 'c')
add_global_arguments('-U_FORTIFY_SOURCE', language : 'c')
add_global_arguments('-D_FORTIFY_SOURCE=0', language : 'c')
add_global_arguments('-DWINE_UNICODE_NATIVE', language : 'c')
#add_global_link_arguments('-Wl,--no-as-needed', language : 'c')

add_global_arguments('-D__WINESRC__', language : 'cpp')
#add_global_arguments('-m64', language : 'cpp')
#add_global_arguments('-fPIC', language : 'cpp')
add_global_arguments('-fno-strict-aliasing', language : 'cpp')
add_global_arguments('-Wall', language : 'cpp')
add_global_arguments('-Wdeclaration-after-statement', language : 'cpp')
#add_global_arguments('-Wempty-body', language : 'cpp')
add_global_arguments('-Wignored-qualifiers', language : 'cpp')
#add_global_arguments('-Wno-packed-not-aligned', language : 'cpp')
add_global_arguments('-Wshift-overflow=2', language : 'cpp')
add_global_arguments('-Wstrict-prototypes', language : 'cpp')
add_global_arguments('-Wtype-limits', language : 'cpp')
add_global_arguments('-Wvla', language : 'cpp')
add_global_arguments('-Wwrite-strings', language : 'cpp')
add_global_arguments('-Wpointer-arith', language : 'cpp')
add_global_arguments('-Wlogical-op', language : 'cpp')
add_global_arguments('-Werror=implicit-function-declaration', language : 'cpp')
#add_global_arguments('-Werror=incompatible-pointer-types', language : 'cpp')
add_global_arguments('-g', language : 'cpp')
add_global_arguments('-gdwarf-2', language : 'cpp')
add_global_arguments('-gstrict-dwarf', language : 'cpp')
add_global_arguments('-U_FORTIFY_SOURCE', language : 'cpp')
add_global_arguments('-D_FORTIFY_SOURCE=0', language : 'cpp')
add_global_arguments('-DWINE_UNICODE_NATIVE', language : 'cpp')
#add_global_link_arguments('-Wl,--no-as-needed', language : 'cpp')

flex = find_program('flex')
bison = find_program('bison')
patchelf_program = find_program('patchelf')

compiler = meson.get_compiler('c')

conf_data = configuration_data()

conf_data.set('DECLSPEC_HOTPATCH', '__attribute__((__ms_hook_prologue__))')

conf_data.set_quoted('PACKAGE_BUGREPORT', 'wine-devel@winehq.org')
conf_data.set_quoted('PACKAGE_NAME', 'Wine')
conf_data.set_quoted('PACKAGE_STRING', 'Wine 3.0')
conf_data.set_quoted('PACKAGE_TARNAME', 'wine')
conf_data.set_quoted('PACKAGE_URL', 'https://www.winehq.org')
conf_data.set_quoted('PACKAGE_VERSION', '3.0')

conf_data.set_quoted('EXEEXT', '')

check_headers = [
    'sys/stat.h',
    'sys/types.h',

    'netinet/ip.h',
    'net/if.h',
    'net/if_arp.h',
    'net/if_dl.h',
    'net/if_types.h',
    'net/route.h',
    'netinet/if_ether.h',
    'netinet/if_inarp.h',
    'netinet/in_pcb.h',
    'netinet/ip_icmp.h',
    'netinet/ip_var.h',
    'netinet/udp.h',
    'netipx/ipx.h',
    'sys/un.h',

    'AL/al.h',
    'ApplicationServices/ApplicationServices.h',
    'AudioToolbox/AudioConverter.h',
    'AudioUnit/AudioUnit.h',
    'AudioUnit/AudioComponent.h',
    'CL/cl.h',
    'Carbon/Carbon.h',
    'CommonCrypto/CommonCryptor.h',
    'CoreAudio/CoreAudio.h',
    'CoreServices/CoreServices.h',
    'DiskArbitration/DiskArbitration.h',
    'EGL/egl.h',
    'IOKit/IOKitLib.h',
    'IOKit/hid/IOHIDLib.h',
    'OpenAL/al.h',
    'OpenCL/opencl.h',
    'QuickTime/ImageCompression.h',
    'Security/Security.h',
    'alias.h',
    'alsa/asoundlib.h',
    'arpa/inet.h',
    'arpa/nameser.h',
    'asm/types.h',
    'asm/user.h',
    'curses.h',
    'direct.h',
    'dirent.h',
    'dlfcn.h',
    'elf.h',
    'float.h',
    'fnmatch.h',
    'getopt.h',
    'gettext-po.h',
    'grp.h',
    'gsm.h',
    'gsm/gsm.h',
    'ieeefp.h',
    'inet/mib2.h',
    'io.h',
    'kstat.h',
    'libproc.h',
    'link.h',
    'linux/cdrom.h',
    'linux/compiler.h',
    'linux/filter.h',
    'linux/hdreg.h',
    'linux/hidraw.h',
    'linux/input.h',
    'linux/ioctl.h',
    'linux/joystick.h',
    'linux/major.h',
    'linux/param.h',
    'linux/serial.h',
    'linux/types.h',
    'linux/ucdrom.h',
    'lwp.h',
    'mach-o/nlist.h',
    'mach-o/loader.h',
    'mach/mach.h',
    'mach/machine.h',
    'machine/cpu.h',
    'machine/limits.h',
    'machine/sysarch.h',
    'mntent.h',
    'ncurses.h',
    'netdb.h',
    'netinet/in.h',
    'netinet/in_systm.h',
    'netinet/tcp.h',
    'netinet/tcp_fsm.h',
    'pcap/pcap.h',
    'poll.h',
    'port.h',
    'process.h',
    'pthread.h',
    'pwd.h',
    'sched.h',
    'scsi/scsi.h',
    'scsi/scsi_ioctl.h',
    'scsi/sg.h',
    'stdbool.h',
    'stdint.h',
    'stropts.h',
    'sys/asoundlib.h',
    'sys/attr.h',
    'sys/auxv.h',
    'sys/cdio.h',
    'sys/elf32.h',
    'sys/epoll.h',
    'sys/event.h',
    'sys/exec_elf.h',
    'sys/filio.h',
    'sys/inotify.h',
    'sys/ioctl.h',
    'sys/ipc.h',
    'sys/limits.h',
    'sys/link.h',
    'sys/mman.h',
    'sys/modem.h',
    'sys/msg.h',
    'sys/mtio.h',
    'sys/param.h',
    'sys/poll.h',
    'sys/prctl.h',
    'sys/protosw.h',
    'sys/ptrace.h',
    'sys/queue.h',
    'sys/resource.h',
    'sys/scsiio.h',
    'sys/shm.h',
    'sys/signal.h',
    'sys/socket.h',
    'sys/socketvar.h',
    'sys/sockio.h',
    'sys/statvfs.h',
    'sys/strtio.h',
    'sys/syscall.h',
    'sys/sysinfo.h',
    'sys/tihdr.h',
    'sys/time.h',
    'sys/timeout.h',
    'sys/times.h',
    'sys/uio.h',
    'sys/user.h',
    'sys/utsname.h',
    'sys/vm86.h',
    'sys/vnode.h',
    'sys/wait.h',
    'syscall.h',
    'termios.h',
    'unistd.h',
    'utime.h',
    'valgrind/memcheck.h',
    'valgrind/valgrind.h',
    'zlib.h',
]

foreach check_header : check_headers
    if compiler.has_header(check_header)
        conf_data.set('HAVE_' + check_header.underscorify().to_upper(), 1)
    endif
endforeach

conf_data.set('HAVE_SYS_MOUNT_H', 1)
conf_data.set('HAVE_SYS_STATFS_H', 1)
conf_data.set('HAVE_SYS_SYSCTL_H', 1)
conf_data.set('HAVE_SYS_USER_H', 1)
conf_data.set('HAVE_SYS_VFS_H', 1)

conf_data.set('HAVE_SYS_UN_H', 1)

conf_data.set('HAVE_MODE_T', 1)
conf_data.set('HAVE_SIZE_T', 1)
conf_data.set('HAVE_SSIZE_T', 1)

conf_data.set('HAVE_ACOSH', 1)
conf_data.set('HAVE_ACOSHF', 1)
conf_data.set('HAVE_ASINH', 1)
conf_data.set('HAVE_ASINHF', 1)
conf_data.set('HAVE_ATANH', 1)
conf_data.set('HAVE_ATANHF', 1)
conf_data.set('HAVE_CBRT', 1)
conf_data.set('HAVE_CBRTF', 1)
conf_data.set('HAVE_ERF', 1)
conf_data.set('HAVE_ERFC', 1)
conf_data.set('HAVE_ERFCF', 1)
conf_data.set('HAVE_ERFF', 1)
conf_data.set('HAVE_EXP2', 1)
conf_data.set('HAVE_EXP2F', 1)
conf_data.set('HAVE_EXPM1', 1)
conf_data.set('HAVE_EXPM1F', 1)
conf_data.set('HAVE_LGAMMA', 1)
conf_data.set('HAVE_LGAMMAF', 1)
conf_data.set('HAVE_LLRINT', 1)
conf_data.set('HAVE_LLRINTF', 1)
conf_data.set('HAVE_LLROUND', 1)
conf_data.set('HAVE_LLROUNDF', 1)
conf_data.set('HAVE_LOG1P', 1)
conf_data.set('HAVE_LOG1PF', 1)
conf_data.set('HAVE_LOG2', 1)
conf_data.set('HAVE_LOG2F', 1)
conf_data.set('HAVE_LRINT', 1)
conf_data.set('HAVE_LRINTF', 1)
conf_data.set('HAVE_LROUND', 1)
conf_data.set('HAVE_LROUNDF', 1)
conf_data.set('HAVE_NEARBYINT', 1)
conf_data.set('HAVE_NEARBYINTF', 1)
conf_data.set('HAVE_POWL', 1)
conf_data.set('HAVE_REMAINDER', 1)
conf_data.set('HAVE_REMAINDERF', 1)
conf_data.set('HAVE_RINT', 1)
conf_data.set('HAVE_RINTF', 1)
conf_data.set('HAVE_ROUND', 1)
conf_data.set('HAVE_ROUNDF', 1)
conf_data.set('HAVE_TRUNC', 1)
conf_data.set('HAVE_TRUNCF', 1)

#conf_data.set('HAVE___RES_GET_STATE', 1)
#conf_data.set('HAVE___RES_GETSERVERS', 1)
#conf_data.set('HAVE__FINITE', 1)
#conf_data.set('HAVE__ISNAN', 1)
#conf_data.set('HAVE__PCLOSE', 1)
#conf_data.set('HAVE__POPEN', 1)
#conf_data.set('HAVE__SNPRINTF', 1)
#conf_data.set('HAVE__SPAWNVP', 1)
#conf_data.set('HAVE__STRDUP', 1)
#conf_data.set('HAVE__STRICMP', 1)
#conf_data.set('HAVE__STRNICMP', 1)
#conf_data.set('HAVE__STRTOI64', 1)
#conf_data.set('HAVE__STRTOUI64', 1)
#conf_data.set('HAVE__VSNPRINTF', 1)
conf_data.set('HAVE_ASCTIME_R', 1)
conf_data.set('HAVE_CHSIZE', 1)
conf_data.set('HAVE_DLOPEN', 1)
conf_data.set('HAVE_EPOLL_CREATE', 1)
conf_data.set('HAVE_FFS', 1)
conf_data.set('HAVE_FINITEF', 1)
conf_data.set('HAVE_FNMATCH', 1)
conf_data.set('HAVE_FORK', 1)
conf_data.set('HAVE_FPCLASS', 1)
conf_data.set('HAVE_FSTATFS', 1)
conf_data.set('HAVE_FSTATVFS', 1)
conf_data.set('HAVE_FTRUNCATE', 1)
conf_data.set('HAVE_FUTIMENS', 1)
conf_data.set('HAVE_FUTIMES', 1)
conf_data.set('HAVE_FUTIMESAT', 1)
#conf_data.set('HAVE_GETATTRLIST', 1)
conf_data.set('HAVE_GETAUXVAL', 1)
conf_data.set('HAVE_GETIFADDRS', 1)
conf_data.set('HAVE_GETOPT_LONG_ONLY', 1)
conf_data.set('HAVE_GETPWUID', 1)
conf_data.set('HAVE_GETTIMEOFDAY', 1)
conf_data.set('HAVE_GETUID', 1)
conf_data.set('HAVE_ISNANF', 1)
conf_data.set('HAVE_KQUEUE', 1)
conf_data.set('HAVE_LSTAT', 1)
conf_data.set('HAVE_MEMMOVE', 1)
conf_data.set('HAVE_MMAP', 1)
conf_data.set('HAVE_PCLOSE', 1)
conf_data.set('HAVE_PIPE2', 1)
conf_data.set('HAVE_POLL', 1)
conf_data.set('HAVE_POPEN', 1)
conf_data.set('HAVE_PORT_CREATE', 1)
conf_data.set('HAVE_PRCTL', 1)
conf_data.set('HAVE_PREAD', 1)
conf_data.set('HAVE_PROC_PIDINFO', 1)
conf_data.set('HAVE_PWRITE', 1)
conf_data.set('HAVE_READDIR', 1)
conf_data.set('HAVE_READLINK', 1)
conf_data.set('HAVE_SCHED_YIELD', 1)
conf_data.set('HAVE_SELECT', 1)
#conf_data.set('HAVE_SETPROCTITLE', 1)
#conf_data.set('HAVE_SETPROGNAME', 1)
conf_data.set('HAVE_SETRLIMIT', 1)
conf_data.set('HAVE_SETTIMEOFDAY', 1)
conf_data.set('HAVE_SIGALTSTACK', 1)
conf_data.set('HAVE_SIGPROCMASK', 1)
conf_data.set('HAVE_SNPRINTF', 1)
conf_data.set('HAVE_STATFS', 1)
conf_data.set('HAVE_STATVFS', 1)
conf_data.set('HAVE_STRCASECMP', 1)
conf_data.set('HAVE_STRDUP', 1)
conf_data.set('HAVE_STRERROR', 1)
conf_data.set('HAVE_STRNCASECMP', 1)
conf_data.set('HAVE_STRNLEN', 1)
conf_data.set('HAVE_STRTOLD', 1)
conf_data.set('HAVE_STRTOLL', 1)
conf_data.set('HAVE_STRTOULL', 1)
conf_data.set('HAVE_SYMLINK', 1)
conf_data.set('HAVE_SYSINFO', 1)
conf_data.set('HAVE_TCDRAIN', 1)
conf_data.set('HAVE_THR_KILL2', 1)
conf_data.set('HAVE_TIMEGM', 1)
conf_data.set('HAVE_USLEEP', 1)
conf_data.set('HAVE_VSNPRINTF', 1)

conf_data.set('HAVE_GETADDRINFO', 1)
conf_data.set('HAVE_GETNAMEINFO', 1)
conf_data.set('HAVE_GETNETBYNAME', 1)
conf_data.set('HAVE_GETPROTOBYNAME', 1)
conf_data.set('HAVE_GETPROTOBYNUMBER', 1)
conf_data.set('HAVE_GETSERVBYPORT', 1)
conf_data.set('HAVE_INET_ADDR', 1)
conf_data.set('HAVE_INET_NETWORK', 1)
conf_data.set('HAVE_INET_NTOP', 1)
conf_data.set('HAVE_INET_PTON', 1)
conf_data.set('HAVE_SENDMSG', 1)
conf_data.set('HAVE_SOCKETPAIR', 1)

conf_data.set('HAVE_TIMEZONE', 1)
conf_data.set('HAVE_DAYLIGHT', 1)
conf_data.set('HAVE_ISFINITE', 1)
conf_data.set('HAVE_ISINF', 1)
conf_data.set('HAVE_ISNAN', 1)

if compiler.has_member('struct option', 'name', prefix: '#include <getopt.h>')
    conf_data.set('HAVE_STRUCT_OPTION_NAME', 1)
endif
if compiler.has_member('struct statvfs', 'f_blocks', prefix: '#include <sys/statvfs.h>')
    conf_data.set('HAVE_STRUCT_STATVFS_F_BLOCKS', 1)
endif
if compiler.has_member('struct sockaddr_un', 'sun_len', prefix: '#include <sys/un.h>')
    conf_data.set('HAVE_STRUCT_SOCKADDR_UN_SUN_LEN', 1)
endif
if compiler.has_member('struct ifreq', 'ifr_hwaddr', prefix: '''
    #include <sys/types.h>
    #include <if/net.h>
''')
    conf_data.set('HAVE_STRUCT_IFREQ_IFR_HWADDR', 1)
endif

configure_file(
    input: 'include/config.h.meson.in',
    output: 'config.h',
    configuration: conf_data,
)

base_include_dep = declare_dependency(
    include_directories: [
        include_directories('.'),
        include_directories('include'),
    ]
)

subdir('libs')
subdir('tools')
subdir('include')
subdir('dlls')

pkgconfig = import('pkgconfig')

pkgconfig.generate(
    name: 'winapi',
    description: 'Wine implementation of Winapi.',
    version: '1.0',
    filebase: 'winapi',
    subdirs: [
        'winapi',
    ],
    libraries: [
        dlls_winecrt0_lib,
        dlls_ntdll_lib,
        dlls_kernel32_lib,
        dlls_advapi32_lib,
        dlls_gdi32_lib,
        dlls_user32_lib,
    ],
)

pkgconfig.generate(
    name: 'winapi-d3dcompiler_43',
    description: 'Wine implementation of Winapi D3DCompiler.',
    version: '1.0',
    filebase: 'winapi-d3dcompiler_43',
    subdirs: [
        'winapi',
    ],
    libraries: [
        dlls_d3dcompiler_43_lib,
    ],
)

pkgconfig.generate(
    name: 'winapi-d3dcompiler_46',
    description: 'Wine implementation of Winapi D3DCompiler.',
    version: '1.0',
    filebase: 'winapi-d3dcompiler_46',
    subdirs: [
        'winapi',
    ],
    libraries: [
        dlls_d3dcompiler_46_lib,
    ],
)

pkgconfig.generate(
    name: 'winapi-d3dcompiler_47',
    description: 'Wine implementation of Winapi D3DCompiler.',
    version: '1.0',
    filebase: 'winapi-d3dcompiler_47',
    subdirs: [
        'winapi',
    ],
    libraries: [
        dlls_d3dcompiler_47_lib,
    ],
)
