/*
 * Window messaging support
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

#include <QWindow>

#include "user_private.hpp"

/***********************************************************************
 *		PostQuitMessage  (USER32.@)
 *
 * Posts a quit message to the current thread's message queue.
 *
 * PARAMS
 *  exit_code [I] Exit code to return from message loop.
 *
 * RETURNS
 *  Nothing.
 *
 * NOTES
 *  This function is not the same as calling:
 *|PostThreadMessage(GetCurrentThreadId(), WM_QUIT, exit_code, 0);
 *  It instead sets a flag in the message queue that signals it to generate
 *  a WM_QUIT message when there are no other pending sent or posted messages
 *  in the queue.
 */
void WINAPI PostQuitMessage(INT exit_code)
{
    QCoreApplication::exit(exit_code);
}

UINT_PTR WINAPI SetCoalescableTimer( HWND hwnd, UINT_PTR id, UINT timeout, TIMERPROC proc, ULONG tolerance )
{
    UINT_PTR ret;
    WNDPROC winproc = 0;

    if (proc) winproc = WINPROC_AllocProc( (WNDPROC)proc, FALSE );

    timeout = min( max( USER_TIMER_MINIMUM, timeout ), USER_TIMER_MAXIMUM );


    //TRACE("Added %p %lx %p timeout %d\n", hwnd, id, winproc, timeout );
    return ret;
}


/***********************************************************************
 *		SetSystemTimer (USER32.@)
 */
UINT_PTR WINAPI SetSystemTimer( HWND hwnd, UINT_PTR id, UINT timeout, TIMERPROC proc )
{
    UINT_PTR ret;
    WNDPROC winproc = 0;

    if (proc) winproc = WINPROC_AllocProc( (WNDPROC)proc, FALSE );

    timeout = min( max( USER_TIMER_MINIMUM, timeout ), USER_TIMER_MAXIMUM );


    //TRACE("Added %p %lx %p timeout %d\n", hwnd, id, winproc, timeout );
    return ret;
}

/***********************************************************************
 *		KillTimer (USER32.@)
 */
BOOL WINAPI KillTimer( HWND hwnd, UINT_PTR id )
{
    QWindow *window = (QWindow *)hwnd;
    window->killTimer((int)id);
}
