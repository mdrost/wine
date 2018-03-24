/*
 * Copyright 2014 Jacek Caban for CodeWeavers
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

#define COBJMACROS

#include "windows.h"
#include "wine/heap.h"
#include "ole2.h"
#include "wmp.h"

typedef struct {
    IConnectionPoint IConnectionPoint_iface;

    IConnectionPointContainer *container;

    IDispatch **sinks;
    DWORD sinks_size;

    IID iid;
} ConnectionPoint;

struct WindowsMediaPlayer {
    IOleObject IOleObject_iface;
    IProvideClassInfo2 IProvideClassInfo2_iface;
    IPersistStreamInit IPersistStreamInit_iface;
    IOleInPlaceObjectWindowless IOleInPlaceObjectWindowless_iface;
    IConnectionPointContainer IConnectionPointContainer_iface;
    IOleControl IOleControl_iface;
    IWMPPlayer4 IWMPPlayer4_iface;
    IWMPPlayer IWMPPlayer_iface;
    IWMPSettings IWMPSettings_iface;
    IWMPControls IWMPControls_iface;

    LONG ref;

    IOleClientSite *client_site;
    HWND hwnd;
    SIZEL extent;

    /* Settings */
    VARIANT_BOOL auto_start;
    VARIANT_BOOL invoke_urls;
    VARIANT_BOOL enable_error_dialogs;

    ConnectionPoint *wmpocx;
};

void init_player(WindowsMediaPlayer*) DECLSPEC_HIDDEN;
void ConnectionPointContainer_Init(WindowsMediaPlayer *wmp) DECLSPEC_HIDDEN;
void ConnectionPointContainer_Destroy(WindowsMediaPlayer *wmp) DECLSPEC_HIDDEN;

HRESULT WINAPI WMPFactory_CreateInstance(IClassFactory*,IUnknown*,REFIID,void**) DECLSPEC_HIDDEN;

void unregister_wmp_class(void) DECLSPEC_HIDDEN;

extern HINSTANCE wmp_instance DECLSPEC_HIDDEN;

static inline void* __WINE_ALLOC_SIZE(1) heap_alloc(size_t len)
{
    return heap_alloc(len);
}

static inline void* __WINE_ALLOC_SIZE(1) heap_alloc_zero(size_t len)
{
    return heap_alloc_zero(len);
}

static inline BOOL heap_free(void *mem)
{
    return heap_free(mem);
}
