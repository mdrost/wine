/*
 * Implementation of svchost.exe
 *
 * Copyright 2007 Google (Roy Shea)
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

/* Usage:
 * Starting a service group:
 *
 *      svchost /k service_group_name
 */

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "winsvc.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(svchost);

/* Static strings used throughout svchost */
static const WCHAR kd[] = {'-','k',0};

static const WCHAR ks[] = {'/','k',0};

static const WCHAR reg_separator[] = {'\\',0};

static const WCHAR service_reg_path[] = {
    'S','y','s','t','e','m',
    '\\','C','u','r','r','e','n','t','C','o','n','t','r','o','l','S','e','t',
    '\\','S','e','r','v','i','c','e','s',0};

static const WCHAR parameters[] = {
    'P','a','r','a','m','e','t','e','r','s',0};

static const WCHAR service_dll[] = {
    'S','e','r','v','i','c','e','D','l','l',0};

static const WCHAR svchost_path[] = {
    'S','o','f','t','w','a','r','e',
    '\\','M','i','c','r','o','s','o','f','t',
    '\\','W','i','n','d','o','w','s',' ','N','T',
    '\\','C','u','r','r','e','n','t','V','e','r','s','i','o','n',
    '\\','S','v','c','h','o','s','t',0};

static const CHAR service_main[] = "ServiceMain";

/* Allocate and initialize a WSTR containing the queried value */
static LPWSTR GetRegValue(HKEY service_key, const WCHAR *value_name)
{
    DWORD type;
    DWORD reg_size;
    DWORD size;
    LONG ret;
    LPWSTR value;

    WINE_TRACE("\n");

    ret = RegQueryValueExW(service_key, value_name, NULL, &type, NULL, &reg_size);
    if (ret != ERROR_SUCCESS)
    {
        return NULL;
    }

    /* Add space for potentially missing NULL terminators in initial alloc.
     * The worst case REG_MULTI_SZ requires two NULL terminators. */
    size = reg_size + (2 * sizeof(WCHAR));
    value = heap_alloc(size);

    ret = RegQueryValueExW(service_key, value_name, NULL, &type,
            (LPBYTE)value, &reg_size);
    if (ret != ERROR_SUCCESS)
    {
        heap_free(value);
        return NULL;
    }

    /* Explicitly NULL terminate the result */
    value[size / sizeof(WCHAR) - 1] = '\0';
    value[size / sizeof(WCHAR) - 2] = '\0';

    return value;
}

/* Allocate and initialize a WSTR containing the expanded string */
static LPWSTR ExpandEnv(LPWSTR string)
{
    DWORD size;
    LPWSTR expanded_string;

    WINE_TRACE("\n");

    size = 0;
    size = ExpandEnvironmentStringsW(string, NULL, size);
    if (size == 0)
    {
        WINE_ERR("cannot expand env vars in %s: %u\n",
                wine_dbgstr_w(string), GetLastError());
        return NULL;
    }
    expanded_string = HeapAlloc(GetProcessHeap(), 0,
            (size + 1) * sizeof(WCHAR));
    if (ExpandEnvironmentStringsW(string, expanded_string, size) == 0)
    {
        WINE_ERR("cannot expand env vars in %s: %u\n",
                wine_dbgstr_w(string), GetLastError());
        heap_free(expanded_string);
        return NULL;
    }
    return expanded_string;
}

/* Fill in service table entry for a specified service */
static BOOL AddServiceElem(LPWSTR service_name,
        SERVICE_TABLE_ENTRYW *service_table_entry)
{
    LONG ret;
    HKEY service_hkey = NULL;
    LPWSTR service_param_key = NULL;
    LPWSTR dll_name_short = NULL;
    LPWSTR dll_name_long = NULL;
    LPSTR dll_service_main = NULL;
    HMODULE library = NULL;
    LPSERVICE_MAIN_FUNCTIONW service_main_func = NULL;
    BOOL success = FALSE;
    DWORD reg_size;
    DWORD size;

    WINE_TRACE("Adding element for %s\n", wine_dbgstr_w(service_name));

    /* Construct registry path to the service's parameters key */
    size = (lstrlenW(service_reg_path) + lstrlenW(reg_separator) +
            lstrlenW(service_name) + lstrlenW(reg_separator) +
            lstrlenW(parameters) + 1);
    service_param_key = heap_alloc(size * sizeof(WCHAR));
    lstrcpyW(service_param_key, service_reg_path);
    lstrcatW(service_param_key, reg_separator);
    lstrcatW(service_param_key, service_name);
    lstrcatW(service_param_key, reg_separator);
    lstrcatW(service_param_key, parameters);
    service_param_key[size - 1] = '\0';
    ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, service_param_key, 0,
            KEY_READ, &service_hkey);
    if (ret != ERROR_SUCCESS)
    {
        WINE_ERR("cannot open key %s, err=%d\n",
                wine_dbgstr_w(service_param_key), ret);
        goto cleanup;
    }

    /* Find DLL associate with service from key */
    dll_name_short = GetRegValue(service_hkey, service_dll);
    if (!dll_name_short)
    {
        WINE_ERR("cannot find registry value %s for service %s\n",
                wine_dbgstr_w(service_dll), wine_dbgstr_w(service_name));
        RegCloseKey(service_hkey);
        goto cleanup;
    }

    /* Expand environment variables in ServiceDll name*/
    dll_name_long = ExpandEnv(dll_name_short);
    if (!dll_name_long)
    {
        WINE_ERR("failed to expand string %s\n",
                wine_dbgstr_w(dll_name_short));
        RegCloseKey(service_hkey);
        goto cleanup;
    }

    /* Look for alternate to default ServiceMain entry point */
    ret = RegQueryValueExA(service_hkey, service_main, NULL, NULL, NULL, &reg_size);
    if (ret == ERROR_SUCCESS)
    {
        /* Add space for potentially missing NULL terminator, allocate, and
         * fill with the registry value */
        size = reg_size + 1;
        dll_service_main = heap_alloc(size);
        ret = RegQueryValueExA(service_hkey, service_main, NULL, NULL,
                (LPBYTE)dll_service_main, &reg_size);
        if (ret != ERROR_SUCCESS)
        {
            RegCloseKey(service_hkey);
            goto cleanup;
        }
        dll_service_main[size - 1] = '\0';
    }
    RegCloseKey(service_hkey);

    /* Load the DLL and obtain a pointer to ServiceMain entry point */
    library = LoadLibraryExW(dll_name_long, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!library)
    {
        WINE_ERR("failed to load library %s, err=%u\n",
                wine_dbgstr_w(dll_name_long), GetLastError());
        goto cleanup;
    }
    if (dll_service_main)
    {
        service_main_func =
            (LPSERVICE_MAIN_FUNCTIONW) GetProcAddress(library, dll_service_main);
    }
    else
    {
        service_main_func =
            (LPSERVICE_MAIN_FUNCTIONW) GetProcAddress(library, service_main);
    }
    if (!service_main_func)
    {
        WINE_ERR("cannot locate ServiceMain procedure in DLL for %s\n",
                wine_dbgstr_w(service_name));
        FreeLibrary(library);
        goto cleanup;
    }

    if (GetProcAddress(library, "SvchostPushServiceGlobals"))
    {
        WINE_FIXME("library %s expects undocumented SvchostPushServiceGlobals function to be called\n",
                   wine_dbgstr_w(dll_name_long));
    }

    /* Fill in the service table entry */
    service_table_entry->lpServiceName = service_name;
    service_table_entry->lpServiceProc = service_main_func;
    success = TRUE;

cleanup:
    heap_free(service_param_key);
    heap_free(dll_name_short);
    heap_free(dll_name_long);
    heap_free(dll_service_main);
    return success;
}

/* Initialize the service table for a list (REG_MULTI_SZ) of services */
static BOOL StartGroupServices(LPWSTR services)
{
    LPWSTR service_name = NULL;
    SERVICE_TABLE_ENTRYW *service_table = NULL;
    DWORD service_count;
    BOOL ret;

    /* Count the services to load */
    service_count = 0;
    service_name = services;
    while (*service_name != '\0')
    {
        ++service_count;
        service_name = service_name + lstrlenW(service_name);
        ++service_name;
    }
    WINE_TRACE("Service group contains %d services\n", service_count);

    /* Populate the service table */
    service_table = HeapAlloc(GetProcessHeap(), 0,
            (service_count + 1) * sizeof(SERVICE_TABLE_ENTRYW));
    service_count = 0;
    service_name = services;
    while (*service_name != '\0')
    {
        if (!AddServiceElem(service_name, &service_table[service_count]))
        {
            heap_free(service_table);
            return FALSE;
        }
        ++service_count;
        service_name = service_name + lstrlenW(service_name);
        ++service_name;
    }
    service_table[service_count].lpServiceName = NULL;
    service_table[service_count].lpServiceProc = NULL;

    /* Start the services */
    if (!(ret = StartServiceCtrlDispatcherW(service_table)))
        WINE_ERR("StartServiceCtrlDispatcherW failed to start %s: %u\n",
                wine_dbgstr_w(services), GetLastError());

    heap_free(service_table);
    return ret;
}

/* Find the list of services associated with a group name and start those
 * services */
static BOOL LoadGroup(PWCHAR group_name)
{
    HKEY group_hkey = NULL;
    LPWSTR services = NULL;
    LONG ret;

    WINE_TRACE("Loading service group for %s\n", wine_dbgstr_w(group_name));

    /* Lookup group_name value of svchost registry entry */
    ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, svchost_path, 0,
            KEY_READ, &group_hkey);
    if (ret != ERROR_SUCCESS)
    {
        WINE_ERR("cannot open key %s, err=%d\n",
                wine_dbgstr_w(svchost_path), ret);
        return FALSE;
    }
    services = GetRegValue(group_hkey, group_name);
    RegCloseKey(group_hkey);
    if (!services)
    {
        WINE_ERR("cannot find registry value %s in %s\n",
                wine_dbgstr_w(group_name), wine_dbgstr_w(svchost_path));
        return FALSE;
    }

    /* Start services */
    if (!(ret = StartGroupServices(services)))
        WINE_TRACE("Failed to start service group\n");

    heap_free(services);
    return ret;
}

/* Load svchost group specified on the command line via the /k option */
int wmain(int argc, WCHAR *argv[])
{
    int option_index;

    WINE_TRACE("\n");

    for (option_index = 1; option_index < argc; option_index++)
    {
        if (lstrcmpiW(argv[option_index], ks) == 0 ||
                lstrcmpiW(argv[option_index], kd) == 0)
        {
            ++option_index;
            if (option_index >= argc)
            {
                WINE_ERR("Must specify group to initialize\n");
                return 0;
            }
            if (!LoadGroup(argv[option_index]))
            {
                WINE_ERR("Failed to load requested group: %s\n",
                        wine_dbgstr_w(argv[option_index]));
                return 0;
            }
        }
        else
        {
            WINE_FIXME("Unrecognized option: %s\n",
                    wine_dbgstr_w(argv[option_index]));
            return 0;
        }
    }

    return 0;
}
