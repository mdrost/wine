/*
 * USER private definitions
 *
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

#ifndef __WINE_USER_PRIVATE_HPP
#define __WINE_USER_PRIVATE_HPP

#include <QApplication>
#include <QMap>

#include "windef.h"
#include "winbase.h"
#include "wingdi.h"
#include "winuser.h"

#include "user_private.h"

class WineApplication : public QApplication
{
public:
    WineApplication(int &argc, char **argv);
    
private:
    QMap<ATOM, const WNDCLASSA *> classes;
    QMap<QPair<QWindow *, UINT_PTR>, int> timers;
};

#endif /* __WINE_USER_PRIVATE_HPP */
