/*
 * Copyright 2018 Mateusz Drost
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "config.h"
#include "wine/port.h"

#include <errno.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "winerror.h"
#include "wine/error.h"

NTSTATUS wine_errno_to_status(int err)
{
    switch(err)
    {
    case EPERM: break;
    case ENOENT: break;
    case ESRCH: return STATUS_INVALID_PARAMETER;
    case EINTR: break;
    case EIO: break;
    case ENXIO: break;
    case E2BIG: break;
    case ENOEXEC: break;
    case EBADF: break;
    case ECHILD: break;
    case EAGAIN: return STATUS_INSUFFICIENT_RESOURCES;
    case ENOMEM: return STATUS_NO_MEMORY;
    case EACCES: break;
    case EFAULT: break;
    case ENOTBLK: break;
    case EBUSY: break;
    case EEXIST: break;
    case EXDEV: break;
    case ENODEV: break;
    case ENOTDIR: break;
    case EISDIR: break;
    case EINVAL: return STATUS_INVALID_PARAMETER;
    case ENFILE: break;
    case EMFILE: return STATUS_TOO_MANY_OPENED_FILES;
    case ENOTTY: break;
    case ETXTBSY: break;
    case EFBIG: break;
    case ENOSPC: return STATUS_DISK_FULL;
    case ESPIPE: break;
    case EROFS: break;
    case EMLINK: break;
    case EPIPE: break;
    case EDOM: break;
    case ERANGE: break;
    case EDEADLK: break;
    case ENAMETOOLONG: return STATUS_NAME_TOO_LONG;
    case ENOLCK: break;
    case ENOSYS: return STATUS_NOT_IMPLEMENTED;
    case ENOTEMPTY: return STATUS_DIRECTORY_NOT_EMPTY;
    case ELOOP: break;
#if EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK: return STATUS_CANT_WAIT;
#endif
    case ENOMSG: break;
    case EIDRM: break;
    case ECHRNG: break;
    case EL2NSYNC: break;
    case EL3HLT: break;
    case EL3RST: break;
    case ELNRNG: break;
    case EUNATCH: break;
    case ENOCSI: break;
    case EL2HLT: break;
    case EBADE: break;
    case EBADR: break;
    case EXFULL: break;
    case ENOANO: break;
    case EBADRQC: break;
    case EBADSLT: break;
#if EDEADLOCK != EDEADLK
    case EDEADLOCK: break;
#endif
    case EBFONT: break;
    case ENOSTR: break;
    case ENODATA: break;
    case ETIME: break;
    case ENOSR: break;
    case ENONET: break;
    case ENOPKG: break;
    case EREMOTE: break;
    case ENOLINK: break;
    case EADV: break;
    case ESRMNT: break;
    case ECOMM: break;
    case EPROTO: break;
    case EMULTIHOP: break;
    case EDOTDOT: break;
    case EBADMSG: break;
    case EOVERFLOW: break;
    case ENOTUNIQ: break;
    case EBADFD: break;
    case EREMCHG: break;
    case ELIBACC: break;
    case ELIBBAD: break;
    case ELIBSCN: break;
    case ELIBMAX: break;
    case ELIBEXEC: break;
    case EILSEQ: break;
    case ERESTART: break;
    case ESTRPIPE: break;
    case EUSERS: break;
    case ENOTSOCK: break;
    case EDESTADDRREQ: break;
    case EMSGSIZE: break;
    case EPROTOTYPE: break;
    case ENOPROTOOPT: break;
    case EPROTONOSUPPORT: break;
    case ESOCKTNOSUPPORT: break;
    case EOPNOTSUPP: return STATUS_NOT_SUPPORTED;
    case EPFNOSUPPORT: break;
    case EAFNOSUPPORT: break;
    case EADDRINUSE: break;
    case EADDRNOTAVAIL: break;
    case ENETDOWN: break;
    case ENETUNREACH: break;
    case ENETRESET: break;
    case ECONNABORTED: break;
    case ECONNRESET: break;
    case ENOBUFS: break;
    case EISCONN: break;
    case ENOTCONN: break;
    case ESHUTDOWN: break;
    case ETOOMANYREFS: break;
    case ETIMEDOUT: break;
    case ECONNREFUSED: break;
    case EHOSTDOWN: break;
    case EHOSTUNREACH: break;
    case EALREADY: break;
    case EINPROGRESS: break;
    case ESTALE: break;
    case EUCLEAN: break;
    case ENOTNAM: break;
    case ENAVAIL: break;
    case EISNAM: break;
    case EREMOTEIO: break;
    case EDQUOT: break;
    case ENOMEDIUM: break;
    case EMEDIUMTYPE: break;
    case ECANCELED: break;
    case ENOKEY: break;
    case EKEYEXPIRED: break;
    case EKEYREVOKED: break;
    case EKEYREJECTED: break;
    case EOWNERDEAD: break;
    case ENOTRECOVERABLE: break;
    case ERFKILL: break;
    case EHWPOISON: break;
#if ENOTSUP != EOPNOTSUPP
    case ENOTSUP: return STATUS_NOT_SUPPORTED;
#endif
    }
    return STATUS_UNSUCCESSFUL;
}

ULONG wine_errno_to_error(int err)
{
    switch(err)
    {
    case EPERM: break;
    case ENOENT: break;
    case ESRCH: return ERROR_INVALID_PARAMETER;
    case EINTR: break;
    case EIO: break;
    case ENXIO: break;
    case E2BIG: break;
    case ENOEXEC: break;
    case EBADF: break;
    case ECHILD: break;
    case EAGAIN: return ERROR_NO_SYSTEM_RESOURCES;
    case ENOMEM: return ERROR_NOT_ENOUGH_MEMORY;
    case EACCES: break;
    case EFAULT: return ERROR_INVALID_ADDRESS;
    case ENOTBLK: break;
    case EBUSY: break;
    case EEXIST: break;
    case EXDEV: break;
    case ENODEV: break;
    case ENOTDIR: break;
    case EISDIR: break;
    case EINVAL: return ERROR_INVALID_PARAMETER;
    case ENFILE: break;
    case EMFILE: return ERROR_TOO_MANY_OPEN_FILES;
    case ENOTTY: break;
    case ETXTBSY: break;
    case EFBIG: break;
    case ENOSPC: return ERROR_DISK_FULL;
    case ESPIPE: break;
    case EROFS: break;
    case EMLINK: break;
    case EPIPE: break;
    case EDOM: break;
    case ERANGE: break;
    case EDEADLK: break;
    case ENAMETOOLONG: return ERROR_FILENAME_EXCED_RANGE;
    case ENOLCK: break;
    case ENOSYS: return ERROR_CALL_NOT_IMPLEMENTED;
    case ENOTEMPTY: return ERROR_DIR_NOT_EMPTY;
    case ELOOP: break;
#if EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK: return ERROR_CANT_WAIT;
#endif
    case ENOMSG: break;
    case EIDRM: break;
    case ECHRNG: break;
    case EL2NSYNC: break;
    case EL3HLT: break;
    case EL3RST: break;
    case ELNRNG: break;
    case EUNATCH: break;
    case ENOCSI: break;
    case EL2HLT: break;
    case EBADE: break;
    case EBADR: break;
    case EXFULL: break;
    case ENOANO: break;
    case EBADRQC: break;
    case EBADSLT: break;
#if EDEADLOCK != EDEADLK
    case EDEADLOCK: break;
#endif
    case EBFONT: break;
    case ENOSTR: break;
    case ENODATA: break;
    case ETIME: break;
    case ENOSR: break;
    case ENONET: break;
    case ENOPKG: break;
    case EREMOTE: break;
    case ENOLINK: break;
    case EADV: break;
    case ESRMNT: break;
    case ECOMM: break;
    case EPROTO: break;
    case EMULTIHOP: break;
    case EDOTDOT: break;
    case EBADMSG: break;
    case EOVERFLOW: break;
    case ENOTUNIQ: break;
    case EBADFD: break;
    case EREMCHG: break;
    case ELIBACC: break;
    case ELIBBAD: break;
    case ELIBSCN: break;
    case ELIBMAX: return ERROR_TOO_MANY_MODULES;
    case ELIBEXEC: break;
    case EILSEQ: break;
    case ERESTART: break;
    case ESTRPIPE: break;
    case EUSERS: break;
    case ENOTSOCK: break;
    case EDESTADDRREQ: break;
    case EMSGSIZE: break;
    case EPROTOTYPE: break;
    case ENOPROTOOPT: break;
    case EPROTONOSUPPORT: break;
    case ESOCKTNOSUPPORT: break;
    case EOPNOTSUPP: return ERROR_NOT_SUPPORTED;
    case EPFNOSUPPORT: break;
    case EAFNOSUPPORT: break;
    case EADDRINUSE: break;
    case EADDRNOTAVAIL: break;
    case ENETDOWN: break;
    case ENETUNREACH: break;
    case ENETRESET: break;
    case ECONNABORTED: break;
    case ECONNRESET: break;
    case ENOBUFS: break;
    case EISCONN: break;
    case ENOTCONN: break;
    case ESHUTDOWN: break;
    case ETOOMANYREFS: break;
    case ETIMEDOUT: break;
    case ECONNREFUSED: break;
    case EHOSTDOWN: break;
    case EHOSTUNREACH: break;
    case EALREADY: break;
    case EINPROGRESS: break;
    case ESTALE: break;
    case EUCLEAN: break;
    case ENOTNAM: break;
    case ENAVAIL: break;
    case EISNAM: break;
    case EREMOTEIO: break;
    case EDQUOT: break;
    case ENOMEDIUM: break;
    case EMEDIUMTYPE: break;
    case ECANCELED: break;
    case ENOKEY: break;
    case EKEYEXPIRED: break;
    case EKEYREVOKED: break;
    case EKEYREJECTED: break;
    case EOWNERDEAD: break;
    case ENOTRECOVERABLE: break;
    case ERFKILL: break;
    case EHWPOISON: break;
#if ENOTSUP != EOPNOTSUPP
    case ENOTSUP: return ERROR_NOT_SUPPORTED;
#endif
    }
    return ERROR_MR_MID_NOT_FOUND;
}
 