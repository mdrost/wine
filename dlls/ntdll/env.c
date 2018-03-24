/*
 * Ntdll environment functions
 *
 * Copyright 1996, 1998 Alexandre Julliard
 * Copyright 2003       Eric Pouech
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

#include <assert.h>
#include <stdarg.h>

#define __USE_GNU
#include <unistd.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "wine/unicode.h"
#include "wine/debug.h"
#include "ntdll_misc.h"
#include "winnt.h"

WINE_DEFAULT_DEBUG_CHANNEL(environ);

/******************************************************************************
 *  NtQuerySystemEnvironmentValue		[NTDLL.@]
 */
NTSYSAPI NTSTATUS WINAPI NtQuerySystemEnvironmentValue(PUNICODE_STRING VariableName,
                                                       PWCHAR Value,
                                                       ULONG ValueBufferLength,
                                                       PULONG RequiredLength)
{
    FIXME("(%s, %p, %u, %p), stub\n", debugstr_us(VariableName), Value, ValueBufferLength, RequiredLength);
    return STATUS_NOT_IMPLEMENTED;
}

/******************************************************************************
 *  NtQuerySystemEnvironmentValueEx		[NTDLL.@]
 */
NTSYSAPI NTSTATUS WINAPI NtQuerySystemEnvironmentValueEx(PUNICODE_STRING name, LPGUID vendor,
                                                         PVOID value, PULONG retlength, PULONG attrib)
{
    FIXME("(%s, %s, %p, %p, %p), stub\n", debugstr_us(name), debugstr_guid(vendor), value, retlength, attrib);
    return STATUS_NOT_IMPLEMENTED;
}

#if 0
/******************************************************************************
 *  RtlCreateEnvironment		[NTDLL.@]
 */
NTSTATUS WINAPI RtlCreateEnvironment(BOOLEAN inherit, PWSTR* env)
{
    NTSTATUS    nts;

    TRACE("(%u,%p)!\n", inherit, env);

    if (inherit)
    {
        MEMORY_BASIC_INFORMATION        mbi;

        RtlAcquirePebLock();

        nts = NtQueryVirtualMemory(NtCurrentProcess(),
                                   NtCurrentTeb()->Peb->ProcessParameters->Environment,
                                   0, &mbi, sizeof(mbi), NULL);
        if (nts == STATUS_SUCCESS)
        {
            *env = NULL;
            nts = NtAllocateVirtualMemory(NtCurrentProcess(), (void**)env, 0, &mbi.RegionSize, 
                                          MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (nts == STATUS_SUCCESS)
                memcpy(*env, NtCurrentTeb()->Peb->ProcessParameters->Environment, mbi.RegionSize);
            else *env = NULL;
        }
        RtlReleasePebLock();
    }
    else 
    {
        SIZE_T      size = 1;
        PVOID       addr = NULL;
        nts = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size,
                                      MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (nts == STATUS_SUCCESS) *env = addr;
    }

    return nts;
}

/******************************************************************************
 *  RtlDestroyEnvironment		[NTDLL.@]
 */
NTSTATUS WINAPI RtlDestroyEnvironment(PWSTR env) 
{
    SIZE_T size = 0;

    TRACE("(%p)!\n", env);

    return NtFreeVirtualMemory(NtCurrentProcess(), (void**)&env, &size, MEM_RELEASE);
}
#endif

#if 0
static LPCWSTR ENV_FindVariable(PCWSTR var, PCWSTR name, unsigned namelen)
#else
static LPCSTR ENV_FindVariable(PCSTR var, PCSTR name, unsigned namelen)
#endif
{
#if 0
    for (; *var; var += strlenW(var) + 1)
#else
    for (; *var; var += strlen(var) + 1)
#endif
    {
        /* match var names, but avoid setting a var with a name including a '='
         * (a starting '=' is valid though)
         */
#if 0
        if (strncmpiW(var, name, namelen) == 0 && var[namelen] == '=' &&
            strchrW(var + 1, '=') == var + namelen) 
#else
        if (strncmp(var, name, namelen) == 0 && var[namelen] == '=' &&
            strchr(var + 1, '=') == var + namelen) 
#endif
        {
            return var + namelen + 1;
        }
    }
    return NULL;
}

static PSTR alloc_environ(void)
{
    PSTR ret, ptr;
    int i;
    int len = 0;

    for (i = 0; environ[i] != NULL; ++i)
        len += strlen(environ[i]);
    len += (i + 2);

    if (!(ret = malloc(len))) return NULL;

    ptr = ret;
    for (i = 0; environ[i] != NULL; i++)
    {
        ptr = stpcpy(ptr, environ[i]);
        ptr += 1;
    }
    stpncpy(ptr, "\0", 1);
    
    return ret;
}


/******************************************************************
 *		RtlQueryEnvironmentVariable_A   [NTDLL.@]
 *
 */
NTSTATUS WINAPI RtlQueryEnvironmentVariable_A(PSTR env,
                                              PANSI_STRING name,
                                              PANSI_STRING value)
{
    NTSTATUS    nts = STATUS_VARIABLE_NOT_FOUND;
    PCSTR       var;
    unsigned    namelen;

    TRACE("%p %s %p\n", env, debugstr_as(name), value);

    value->Length = 0;
    namelen = name->Length / sizeof(CHAR);
    if (!namelen) return nts;

    if (!env)
    {
        if (!(var = alloc_environ())) return STATUS_NO_MEMORY;
    }
    else var = env;

    var = ENV_FindVariable(var, name->Buffer, namelen);
    if (var != NULL)
    {
        value->Length = strlen(var) * sizeof(*var);

        if (value->Length <= value->MaximumLength)
        {
            memmove(value->Buffer, var, min(value->Length + sizeof(*var), value->MaximumLength));
            nts = STATUS_SUCCESS;
        }
        else nts = STATUS_BUFFER_TOO_SMALL;
    }

    free(var);

    return nts;
}

/******************************************************************
 *		RtlQueryEnvironmentVariable_U   [NTDLL.@]
 *
 * NOTES: when the buffer is too small, the string is not written, but if the
 *      terminating null char is the only char that cannot be written, then
 *      all chars (except the null) are written and success is returned
 *      (behavior of Win2k at least)
 */
NTSTATUS WINAPI RtlQueryEnvironmentVariable_U(PWSTR env,
                                              PUNICODE_STRING name,
                                              PUNICODE_STRING value)
{
#if 0
    NTSTATUS    nts = STATUS_VARIABLE_NOT_FOUND;
    PCWSTR      var;
    unsigned    namelen;

    TRACE("%p %s %p\n", env, debugstr_us(name), value);

    value->Length = 0;
    namelen = name->Length / sizeof(WCHAR);
    if (!namelen) return nts;

    if (!env)
    {
        RtlAcquirePebLock();
        var = NtCurrentTeb()->Peb->ProcessParameters->Environment;
    }
    else var = env;

    var = ENV_FindVariable(var, name->Buffer, namelen);
    if (var != NULL)
    {
        value->Length = strlenW(var) * sizeof(*var);

        if (value->Length <= value->MaximumLength)
        {
            memmove(value->Buffer, var, min(value->Length + sizeof(*var), value->MaximumLength));
            nts = STATUS_SUCCESS;
        }
        else nts = STATUS_BUFFER_TOO_SMALL;
    }

    if (!env) RtlReleasePebLock();

    return nts;
#else
    return STATUS_NOT_IMPLEMENTED;
#endif
}

/******************************************************************
 *		RtlSetCurrentEnvironment        [NTDLL.@]
 *
 */
void WINAPI RtlSetCurrentEnvironment(PWSTR new_env, PWSTR* old_env)
{
    TRACE("(%p %p)\n", new_env, old_env);

#if 0
    RtlAcquirePebLock();

    if (old_env) *old_env = NtCurrentTeb()->Peb->ProcessParameters->Environment;
    NtCurrentTeb()->Peb->ProcessParameters->Environment = new_env;

    RtlReleasePebLock();
#endif
}


/******************************************************************************
 *  RtlSetEnvironmentVariable		[NTDLL.@]
 */
NTSTATUS WINAPI RtlSetEnvironmentVariable(PWSTR* penv, PUNICODE_STRING name, 
                                          PUNICODE_STRING value)
{
    INT         len, old_size;
    LPWSTR      p, env;
    NTSTATUS    nts = STATUS_VARIABLE_NOT_FOUND;
    MEMORY_BASIC_INFORMATION mbi;

    TRACE("(%p, %s, %s)\n", penv, debugstr_us(name), debugstr_us(value));

    if (!name || !name->Buffer || !name->Length)
        return STATUS_INVALID_PARAMETER_1;

    len = name->Length / sizeof(WCHAR);

    /* variable names can't contain a '=' except as a first character */
    for (p = name->Buffer + 1; p < name->Buffer + len; p++)
        if (*p == '=') return STATUS_INVALID_PARAMETER;

#if 0
    if (!penv)
    {
        RtlAcquirePebLock();
        env = NtCurrentTeb()->Peb->ProcessParameters->Environment;
    } else env = *penv;

    /* compute current size of environment */
    for (p = env; *p; p += strlenW(p) + 1);
    old_size = p + 1 - env;

    /* Find a place to insert the string */
    for (p = env; *p; p += strlenW(p) + 1)
    {
        if (!strncmpiW(name->Buffer, p, len) && (p[len] == '=')) break;
    }
    if (!value && !*p) goto done;  /* Value to remove doesn't exist */

    /* Realloc the buffer */
    len = value ? len + value->Length / sizeof(WCHAR) + 2 : 0;
    if (*p) len -= strlenW(p) + 1;  /* The name already exists */

    if (len < 0)
    {
        LPWSTR next = p + strlenW(p) + 1;  /* We know there is a next one */
        memmove(next + len, next, (old_size - (next - env)) * sizeof(WCHAR));
    }

    nts = NtQueryVirtualMemory(NtCurrentProcess(), env, 0,
                               &mbi, sizeof(mbi), NULL);
    if (nts != STATUS_SUCCESS) goto done;

    if ((old_size + len) * sizeof(WCHAR) > mbi.RegionSize)
    {
        LPWSTR  new_env;
        SIZE_T  new_size = (old_size + len) * sizeof(WCHAR);

        new_env = NULL;
        nts = NtAllocateVirtualMemory(NtCurrentProcess(), (void**)&new_env, 0,
                                      &new_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (nts != STATUS_SUCCESS) goto done;

        memmove(new_env, env, (p - env) * sizeof(WCHAR));
        assert(len > 0);
        memmove(new_env + (p - env) + len, p, (old_size - (p - env)) * sizeof(WCHAR));
        p = new_env + (p - env);

        RtlDestroyEnvironment(env);
        if (!penv) NtCurrentTeb()->Peb->ProcessParameters->Environment = new_env;
        else *penv = new_env;
    }
    else
    {
        if (len > 0) memmove(p + len, p, (old_size - (p - env)) * sizeof(WCHAR));
    }

    /* Set the new string */
    if (value)
    {
        memcpy( p, name->Buffer, name->Length );
        p += name->Length / sizeof(WCHAR);
        *p++ = '=';
        memcpy( p, value->Buffer, value->Length );
        p[value->Length / sizeof(WCHAR)] = 0;
    }
done:
    if (!penv) RtlReleasePebLock();

    return nts;
#else
    return STATUS_NOT_IMPLEMENTED;
#endif
}

/******************************************************************
 *		RtlExpandEnvironmentStrings_A (NTDLL.@)
 *
 */
NTSTATUS WINAPI RtlExpandEnvironmentStrings_A(PCSTR renv, const ANSI_STRING* as_src,
                                              PANSI_STRING as_dst, PULONG plen)
{
    DWORD src_len, len, count, total_size = 1;  /* 1 for terminating '\0' */
    LPCSTR     env, src, p, var;
    LPSTR      dst;

    src = as_src->Buffer;
    src_len = as_src->Length / sizeof(CHAR);
    count = as_dst->MaximumLength / sizeof(CHAR);
    dst = count ? as_dst->Buffer : NULL;

    if (!renv)
    {
#if 0
        RtlAcquirePebLock();
        env = NtCurrentTeb()->Peb->ProcessParameters->Environment;
#else
        env = alloc_environ();
#endif
    }
    else env = renv;

    while (src_len)
    {
        if (*src != '%')
        {
            if ((p = memchr( src, '%', src_len ))) len = p - src;
            else len = src_len;
            var = src;
            src += len;
            src_len -= len;
        }
        else  /* we are at the start of a variable */
        {
            if ((p = memchr( src + 1, '%', src_len - 1 )))
            {
                len = p - src - 1;  /* Length of the variable name */
                if ((var = ENV_FindVariable( env, src + 1, len )))
                {
                    src += len + 2;  /* Skip the variable name */
                    src_len -= len + 2;
                    len = strlen(var);
                }
                else
                {
                    var = src;  /* Copy original name instead */
                    len += 2;
                    src += len;
                    src_len -= len;
                }
            }
            else  /* unfinished variable name, ignore it */
            {
                var = src;
                len = src_len;  /* Copy whole string */
                src += len;
                src_len = 0;
            }
        }
        total_size += len;
        if (dst)
        {
            if (count < len) len = count;
            memcpy(dst, var, len * sizeof(CHAR));
            count -= len;
            dst += len;
        }
    }

#if 0
    if (!renv) RtlReleasePebLock();
#else
    if (!renv) free(env);
#endif

    /* Null-terminate the string */
    if (dst && count) *dst = '\0';

    as_dst->Length = (dst) ? (dst - as_dst->Buffer) * sizeof(CHAR) : 0;
    if (plen) *plen = total_size * sizeof(CHAR);

    return (count) ? STATUS_SUCCESS : STATUS_BUFFER_TOO_SMALL;
}

/******************************************************************
 *		RtlExpandEnvironmentStrings_U (NTDLL.@)
 *
 */
NTSTATUS WINAPI RtlExpandEnvironmentStrings_U(PCWSTR renv, const UNICODE_STRING* us_src,
                                              PUNICODE_STRING us_dst, PULONG plen)
{
#if 0
    DWORD src_len, len, count, total_size = 1;  /* 1 for terminating '\0' */
    LPCWSTR     env, src, p, var;
    LPWSTR      dst;

    src = us_src->Buffer;
    src_len = us_src->Length / sizeof(WCHAR);
    count = us_dst->MaximumLength / sizeof(WCHAR);
    dst = count ? us_dst->Buffer : NULL;

    if (!renv)
    {
        RtlAcquirePebLock();
        env = NtCurrentTeb()->Peb->ProcessParameters->Environment;
    }
    else env = renv;

    while (src_len)
    {
        if (*src != '%')
        {
            if ((p = memchrW( src, '%', src_len ))) len = p - src;
            else len = src_len;
            var = src;
            src += len;
            src_len -= len;
        }
        else  /* we are at the start of a variable */
        {
            if ((p = memchrW( src + 1, '%', src_len - 1 )))
            {
                len = p - src - 1;  /* Length of the variable name */
                if ((var = ENV_FindVariable( env, src + 1, len )))
                {
                    src += len + 2;  /* Skip the variable name */
                    src_len -= len + 2;
                    len = strlenW(var);
                }
                else
                {
                    var = src;  /* Copy original name instead */
                    len += 2;
                    src += len;
                    src_len -= len;
                }
            }
            else  /* unfinished variable name, ignore it */
            {
                var = src;
                len = src_len;  /* Copy whole string */
                src += len;
                src_len = 0;
            }
        }
        total_size += len;
        if (dst)
        {
            if (count < len) len = count;
            memcpy(dst, var, len * sizeof(WCHAR));
            count -= len;
            dst += len;
        }
    }

    if (!renv) RtlReleasePebLock();

    /* Null-terminate the string */
    if (dst && count) *dst = '\0';

    us_dst->Length = (dst) ? (dst - us_dst->Buffer) * sizeof(WCHAR) : 0;
    if (plen) *plen = total_size * sizeof(WCHAR);

    return (count) ? STATUS_SUCCESS : STATUS_BUFFER_TOO_SMALL;
#else
    return STATUS_NOT_IMPLEMENTED;
#endif
}


static inline void normalize( void *base, WCHAR **ptr )
{
    if (*ptr) *ptr = (WCHAR *)((char *)base + (UINT_PTR)*ptr);
}

/******************************************************************************
 *  RtlNormalizeProcessParams  [NTDLL.@]
 */
PRTL_USER_PROCESS_PARAMETERS WINAPI RtlNormalizeProcessParams( RTL_USER_PROCESS_PARAMETERS *params )
{
    if (params && !(params->Flags & PROCESS_PARAMS_FLAG_NORMALIZED))
    {
        normalize( params, &params->CurrentDirectory.DosPath.Buffer );
        normalize( params, &params->DllPath.Buffer );
        normalize( params, &params->ImagePathName.Buffer );
        normalize( params, &params->CommandLine.Buffer );
        normalize( params, &params->WindowTitle.Buffer );
        normalize( params, &params->Desktop.Buffer );
        normalize( params, &params->ShellInfo.Buffer );
        normalize( params, &params->RuntimeInfo.Buffer );
        params->Flags |= PROCESS_PARAMS_FLAG_NORMALIZED;
    }
    return params;
}


static inline void denormalize( const void *base, WCHAR **ptr )
{
    if (*ptr) *ptr = (WCHAR *)(UINT_PTR)((char *)*ptr - (const char *)base);
}

/******************************************************************************
 *  RtlDeNormalizeProcessParams  [NTDLL.@]
 */
PRTL_USER_PROCESS_PARAMETERS WINAPI RtlDeNormalizeProcessParams( RTL_USER_PROCESS_PARAMETERS *params )
{
    if (params && (params->Flags & PROCESS_PARAMS_FLAG_NORMALIZED))
    {
        denormalize( params, &params->CurrentDirectory.DosPath.Buffer );
        denormalize( params, &params->DllPath.Buffer );
        denormalize( params, &params->ImagePathName.Buffer );
        denormalize( params, &params->CommandLine.Buffer );
        denormalize( params, &params->WindowTitle.Buffer );
        denormalize( params, &params->Desktop.Buffer );
        denormalize( params, &params->ShellInfo.Buffer );
        denormalize( params, &params->RuntimeInfo.Buffer );
        params->Flags &= ~PROCESS_PARAMS_FLAG_NORMALIZED;
    }
    return params;
}


/* append a unicode string to the process params data; helper for RtlCreateProcessParameters */
static void append_unicode_string( void **data, const UNICODE_STRING *src,
                                   UNICODE_STRING *dst )
{
    dst->Length = src->Length;
    dst->MaximumLength = src->MaximumLength;
    dst->Buffer = *data;
    memcpy( dst->Buffer, src->Buffer, dst->MaximumLength );
    *data = (char *)dst->Buffer + dst->MaximumLength;
}


/******************************************************************************
 *  RtlCreateProcessParameters  [NTDLL.@]
 */
NTSTATUS WINAPI RtlCreateProcessParameters( RTL_USER_PROCESS_PARAMETERS **result,
                                            const UNICODE_STRING *ImagePathName,
                                            const UNICODE_STRING *DllPath,
                                            const UNICODE_STRING *CurrentDirectoryName,
                                            const UNICODE_STRING *CommandLine,
                                            PWSTR Environment,
                                            const UNICODE_STRING *WindowTitle,
                                            const UNICODE_STRING *Desktop,
                                            const UNICODE_STRING *ShellInfo,
                                            const UNICODE_STRING *RuntimeInfo )
{
#if 0
    static WCHAR empty[] = {0};
    static const UNICODE_STRING empty_str = { 0, sizeof(empty), empty };
    static const UNICODE_STRING null_str = { 0, 0, NULL };

    const RTL_USER_PROCESS_PARAMETERS *cur_params;
    SIZE_T size, total_size;
    void *ptr;
    NTSTATUS status;

    RtlAcquirePebLock();
    cur_params = NtCurrentTeb()->Peb->ProcessParameters;
    if (!DllPath) DllPath = &cur_params->DllPath;
    if (!CurrentDirectoryName)
    {
        if (NtCurrentTeb()->Tib.SubSystemTib)  /* FIXME: hack */
            CurrentDirectoryName = &((WIN16_SUBSYSTEM_TIB *)NtCurrentTeb()->Tib.SubSystemTib)->curdir.DosPath;
        else
            CurrentDirectoryName = &cur_params->CurrentDirectory.DosPath;
    }
    if (!CommandLine) CommandLine = ImagePathName;
    if (!Environment) Environment = cur_params->Environment;
    if (!WindowTitle) WindowTitle = &empty_str;
    if (!Desktop) Desktop = &empty_str;
    if (!ShellInfo) ShellInfo = &empty_str;
    if (!RuntimeInfo) RuntimeInfo = &null_str;

    size = (sizeof(RTL_USER_PROCESS_PARAMETERS)
            + ImagePathName->MaximumLength
            + DllPath->MaximumLength
            + CurrentDirectoryName->MaximumLength
            + CommandLine->MaximumLength
            + WindowTitle->MaximumLength
            + Desktop->MaximumLength
            + ShellInfo->MaximumLength
            + RuntimeInfo->MaximumLength);

    total_size = size;
    ptr = NULL;
    if ((status = NtAllocateVirtualMemory( NtCurrentProcess(), &ptr, 0, &total_size,
                                           MEM_COMMIT, PAGE_READWRITE )) == STATUS_SUCCESS)
    {
        RTL_USER_PROCESS_PARAMETERS *params = ptr;
        params->AllocationSize = total_size;
        params->Size           = size;
        params->Flags          = PROCESS_PARAMS_FLAG_NORMALIZED;
        params->ConsoleFlags   = cur_params->ConsoleFlags;
        params->Environment    = Environment;
        /* all other fields are zero */

        ptr = params + 1;
        append_unicode_string( &ptr, CurrentDirectoryName, &params->CurrentDirectory.DosPath );
        append_unicode_string( &ptr, DllPath, &params->DllPath );
        append_unicode_string( &ptr, ImagePathName, &params->ImagePathName );
        append_unicode_string( &ptr, CommandLine, &params->CommandLine );
        append_unicode_string( &ptr, WindowTitle, &params->WindowTitle );
        append_unicode_string( &ptr, Desktop, &params->Desktop );
        append_unicode_string( &ptr, ShellInfo, &params->ShellInfo );
        append_unicode_string( &ptr, RuntimeInfo, &params->RuntimeInfo );
        *result = RtlDeNormalizeProcessParams( params );
    }
    RtlReleasePebLock();
    return status;
#else
    return STATUS_NOT_IMPLEMENTED;
#endif
}


/******************************************************************************
 *  RtlDestroyProcessParameters  [NTDLL.@]
 */
void WINAPI RtlDestroyProcessParameters( RTL_USER_PROCESS_PARAMETERS *params )
{
    void *ptr = params;
    SIZE_T size = 0;
    NtFreeVirtualMemory( NtCurrentProcess(), &ptr, &size, MEM_RELEASE );
}
