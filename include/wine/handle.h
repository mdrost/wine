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

#ifndef __WINE_WINE_HANDLE_H
#define __WINE_WINE_HANDLE_H

typedef struct _handle_vtbl
{
    BOOL WINAPI (*close)(HANDLE handle);
    BOOL WINAPI (*duplicate)(HANDLE source_process, HANDLE source, HANDLE dest_process, HANDLE *dest, DWORD access, BOOL inherit, DWORD options);
} handle_vtbl;

#endif  /* __WINE_WINE_HANDLE_H */
