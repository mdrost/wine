/*
 * msvcrtd.dll debugging code
 *
 * Copyright (C) 2003 Adam Gundy
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "wine/debug.h"

#include "winbase.h"

WINE_DEFAULT_DEBUG_CHANNEL(msvcrt);

int _crtAssertBusy = -1;
int _crtBreakAlloc = -1;
int _crtDbgFlag = 0;

extern int _callnewh(unsigned long);

/*********************************************************************
 *		??2@YAPAXIHPBDH@Z (MSVCRTD.@)
 */
void *MSVCRTD_operator_new_dbg(
	unsigned long nSize,
	int nBlockUse,
	const char *szFileName,
	int nLine)
{
    void *retval = HeapAlloc(GetProcessHeap(), 0, nSize);

    TRACE("(%lu, %d, '%s', %d) returning %p\n", nSize, nBlockUse, szFileName, nLine, retval);

    if (!retval)
        _callnewh(nSize);

    return retval;
}

/*********************************************************************
 *		_CrtSetDumpClient (MSVCRTD.@)
 */
void *_CrtSetDumpClient(void *dumpClient)
{
    return NULL;
}


/*********************************************************************
 *		_CrtSetReportHook (MSVCRTD.@)
 */
void *_CrtSetReportHook(void *reportHook)
{
    return NULL;
}


/*********************************************************************
 *		_CrtSetReportMode (MSVCRTD.@)
 */
int _CrtSetReportMode(int reportType, int reportMode)
{
    return 0;
}


/*********************************************************************
 *		_CrtSetBreakAlloc (MSVCRTD.@)
 */
int _CrtSetBreakAlloc(int new)
{
    int old = _crtBreakAlloc;
    _crtBreakAlloc = new;
    return old;
}

/*********************************************************************
 *		_CrtSetDbgFlag (MSVCRTD.@)
 */
int _CrtSetDbgFlag(int new)
{
    int old = _crtDbgFlag;
    _crtDbgFlag = new;
    return old;
}


/*********************************************************************
 *		_CrtDbgReport (MSVCRTD.@)
 */
int _CrtDbgReport(int reportType, const char *filename, int linenumber,
		  const char *moduleName, const char *format, ...)
{
    return 0;
}

/*********************************************************************
 *		_CrtDumpMemoryLeaks (MSVCRTD.@)
 */
int _CrtDumpMemoryLeaks()
{
    return 0;
}

/*********************************************************************
 *		__p__crtAssertBusy (MSVCRTD.@)
 */
int *__p__crtAssertBusy(void)
{
    return &_crtAssertBusy;
}

/*********************************************************************
 *		__p__crtBreakAlloc (MSVCRTD.@)
 */
int *__p__crtBreakAlloc(void)
{
    return &_crtBreakAlloc;
}

/*********************************************************************
 *		__p__crtDbgFlag (MSVCRTD.@)
 */
int *__p__crtDbgFlag(void)
{
    return &_crtDbgFlag;
}
