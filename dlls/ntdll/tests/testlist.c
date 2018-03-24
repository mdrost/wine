#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define STANDALONE
#include "wine/test.h"

#if 0
extern void func_atom(void);
extern void func_change(void);
#endif
extern void func_directory(void);
extern void func_env(void);
#if 0
extern void func_error(void);
extern void func_exception(void);
extern void func_file(void);
extern void func_generated(void);
extern void func_info(void);
#endif
extern void func_large_int(void);
#if 0
extern void func_om(void);
extern void func_path(void);
extern void func_pipe(void);
extern void func_port(void);
extern void func_reg(void);
#endif
extern void func_rtl(void);
extern void func_rtlbitmap(void);
extern void func_rtlstr(void);
extern void func_string(void);
#if 0
extern void func_threadpool(void);
extern void func_time(void);
#endif

const struct test winetest_testlist[] =
{
#if 0
    { "atom", func_atom },
    { "change", func_change },
#endif
    { "directory", func_directory },
    { "env", func_env },
#if 0
    { "error", func_error },
    { "exception", func_exception },
    { "file", func_file },
    { "generated", func_generated },
    { "info", func_info },
#endif
    { "large_int", func_large_int },
#if 0
    { "om", func_om },
    { "path", func_path },
    { "pipe", func_pipe },
    { "port", func_port },
    { "reg", func_reg },
#endif
    { "rtl", func_rtl },
    { "rtlbitmap", func_rtlbitmap },
    { "rtlstr", func_rtlstr },
    { "string", func_string },
#if 0
    { "threadpool", func_threadpool },
    { "time", func_time },
#endif
    { 0, 0 }
};
