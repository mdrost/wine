/*
 * Unit test suite for pathiterator
 *
 * Copyright (C) 2008 Nikolay Sivov
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

#include "windows.h"
#include "gdiplus.h"
#include "wine/test.h"

#define expect(expected, got) ok(got == expected, "Expected %.8x, got %.8x\n", expected, got)

static void test_constructor_destructor(void)
{
    GpPath *path;
    GpPathIterator *iter;
    GpStatus stat;

    GdipCreatePath(FillModeAlternate, &path);
    GdipAddPathRectangle(path, 5.0, 5.0, 100.0, 50.0);

    /* NULL args */
    stat = GdipCreatePathIter(NULL, NULL);
    expect(InvalidParameter, stat);
    stat = GdipCreatePathIter(&iter, NULL);
    expect(Ok, stat);
    stat = GdipCreatePathIter(NULL, path);
    expect(InvalidParameter, stat);
    stat = GdipDeletePathIter(NULL);
    expect(InvalidParameter, stat);

    /* valid args */
    stat = GdipCreatePathIter(&iter, path);
    expect(Ok, stat);

    GdipDeletePathIter(iter);
    GdipDeletePath(path);
}

static void test_hascurve(void)
{
    GpPath *path;
    GpPathIterator *iter;
    GpStatus stat;
    BOOL hasCurve;

    GdipCreatePath(FillModeAlternate, &path);
    GdipAddPathRectangle(path, 5.0, 5.0, 100.0, 50.0);

    stat = GdipCreatePathIter(&iter, path);
    expect(Ok, stat);

    /* NULL args
       BOOL out argument is local in wrapper class method,
       so it always has not-NULL address */
    stat = GdipPathIterHasCurve(NULL, &hasCurve);
    expect(InvalidParameter, stat);

    /* valid args */
    stat = GdipPathIterHasCurve(iter, &hasCurve);
    expect(Ok, stat);
    expect(FALSE, hasCurve);

    GdipDeletePathIter(iter);

    GdipAddPathEllipse(path, 0.0, 0.0, 35.0, 70.0);

    stat = GdipCreatePathIter(&iter, path);
    expect(Ok, stat);

    stat = GdipPathIterHasCurve(iter, &hasCurve);
    expect(Ok, stat);
    expect(TRUE, hasCurve);

    GdipDeletePathIter(iter);
    GdipDeletePath(path);
}

static void test_nextmarker(void)
{
    GpPath *path;
    GpPathIterator *iter;
    GpStatus stat;
    INT start, end;
    INT result;

    /* NULL args
       BOOL out argument is local in wrapper class method,
       so it always has not-NULL address */
    stat = GdipPathIterNextMarker(NULL, &result, NULL, NULL);
    expect(InvalidParameter, stat);
    stat = GdipPathIterNextMarker(NULL, &result, &start, NULL);
    expect(InvalidParameter, stat);
    stat = GdipPathIterNextMarker(NULL, &result, NULL, &end);
    expect(InvalidParameter, stat);

    GdipCreatePath(FillModeAlternate, &path);
    GdipAddPathRectangle(path, 5.0, 5.0, 100.0, 50.0);

    /* no markers */
    GdipCreatePathIter(&iter, path);
    start = end = result = (INT)0xdeadbeef;
    stat = GdipPathIterNextMarker(iter, &result, &start, &end);
    expect(Ok, stat);
    expect(0, start);
    expect(3, end);
    expect(4, result);
    start = end = result = (INT)0xdeadbeef;
    stat = GdipPathIterNextMarker(iter, &result, &start, &end);
    /* start/end remain unchanged */
    expect((INT)0xdeadbeef, start);
    expect((INT)0xdeadbeef, end);
    expect(0, result);
    GdipDeletePathIter(iter);

    /* one marker */
    GdipSetPathMarker(path);
    GdipCreatePathIter(&iter, path);
    start = end = result = (INT)0xdeadbeef;
    stat = GdipPathIterNextMarker(iter, &result, &start, &end);
    expect(Ok, stat);
    expect(0, start);
    expect(3, end);
    expect(4, result);
    start = end = result = (INT)0xdeadbeef;
    stat = GdipPathIterNextMarker(iter, &result, &start, &end);
    expect(Ok, stat);
    expect((INT)0xdeadbeef, start);
    expect((INT)0xdeadbeef, end);
    expect(0, result);
    GdipDeletePathIter(iter);

    /* two markers */
    GdipAddPathLine(path, 0.0, 0.0, 10.0, 30.0);
    GdipSetPathMarker(path);
    GdipCreatePathIter(&iter, path);
    start = end = result = (INT)0xdeadbeef;
    stat = GdipPathIterNextMarker(iter, &result, &start, &end);
    expect(Ok, stat);
    expect(0, start);
    expect(3, end);
    expect(4, result);
    start = end = result = (INT)0xdeadbeef;
    stat = GdipPathIterNextMarker(iter, &result, &start, &end);
    expect(Ok, stat);
    expect(4, start);
    expect(5, end);
    expect(2, result);
    start = end = result = (INT)0xdeadbeef;
    stat = GdipPathIterNextMarker(iter, &result, &start, &end);
    expect(Ok, stat);
    expect((INT)0xdeadbeef, start);
    expect((INT)0xdeadbeef, end);
    expect(0, result);
    GdipDeletePathIter(iter);

    GdipDeletePath(path);
}

static void test_getsubpathcount(void)
{
    GpPath *path;
    GpPathIterator *iter;
    GpStatus stat;
    INT count;

    /* NULL args */
    stat = GdipPathIterGetSubpathCount(NULL, NULL);
    expect(InvalidParameter, stat);
    stat = GdipPathIterGetSubpathCount(NULL, &count);
    expect(InvalidParameter, stat);

    GdipCreatePath(FillModeAlternate, &path);

    /* empty path */
    GdipCreatePathIter(&iter, path);
    stat = GdipPathIterGetSubpathCount(iter, &count);
    expect(Ok, stat);
    expect(0, count);
    GdipDeletePathIter(iter);

    GdipAddPathLine(path, 5.0, 5.0, 100.0, 50.0);

    /* open figure */
    GdipCreatePathIter(&iter, path);
    stat = GdipPathIterGetSubpathCount(iter, &count);
    expect(Ok, stat);
    expect(1, count);
    GdipDeletePathIter(iter);

    /* manually start new figure */
    GdipStartPathFigure(path);
    GdipAddPathLine(path, 50.0, 50.0, 110.0, 40.0);
    GdipCreatePathIter(&iter, path);
    stat = GdipPathIterGetSubpathCount(iter, &count);
    expect(Ok, stat);
    expect(2, count);
    GdipDeletePathIter(iter);

    GdipDeletePath(path);
}

static void test_isvalid(void)
{
    GpPath *path;
    GpPathIterator *iter;
    GpStatus stat;
    BOOL isvalid;
    INT start, end, result;

    GdipCreatePath(FillModeAlternate, &path);

    /* NULL args */
    GdipCreatePathIter(&iter, path);
    stat = GdipPathIterIsValid(NULL, NULL);
    expect(InvalidParameter, stat);
    stat = GdipPathIterIsValid(iter, NULL);
    expect(InvalidParameter, stat);
    stat = GdipPathIterIsValid(NULL, &isvalid);
    expect(InvalidParameter, stat);
    GdipDeletePathIter(iter);

    /* on empty path */
    GdipCreatePathIter(&iter, path);
    isvalid = FALSE;
    stat = GdipPathIterIsValid(iter, &isvalid);
    expect(Ok, stat);
    expect(TRUE, isvalid);
    GdipDeletePathIter(iter);

    /* no markers */
    GdipAddPathLine(path, 50.0, 50.0, 110.0, 40.0);
    GdipCreatePathIter(&iter, path);
    GdipPathIterNextMarker(iter, &result, &start, &end);
    isvalid = FALSE;
    stat = GdipPathIterIsValid(iter, &isvalid);
    expect(Ok, stat);
    expect(TRUE, isvalid);
    GdipDeletePathIter(iter);

    GdipDeletePath(path);
}

START_TEST(pathiterator)
{
    struct GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;

    gdiplusStartupInput.GdiplusVersion              = 1;
    gdiplusStartupInput.DebugEventCallback          = NULL;
    gdiplusStartupInput.SuppressBackgroundThread    = 0;
    gdiplusStartupInput.SuppressExternalCodecs      = 0;

    GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

    test_constructor_destructor();
    test_hascurve();
    test_nextmarker();
    test_getsubpathcount();
    test_isvalid();

    GdiplusShutdown(gdiplusToken);
}
