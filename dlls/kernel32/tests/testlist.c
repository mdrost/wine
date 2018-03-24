#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define STANDALONE
#include "wine/test.h"

#if 0
extern void func_actctx(void);
extern void func_atom(void);
extern void func_change(void);
#endif
extern void func_codepage(void);
#if 0
extern void func_comm(void);
extern void func_console(void);
extern void func_debugger(void);
extern void func_directory(void);
extern void func_drive(void);
#endif
extern void func_environ(void);
#if 0
extern void func_fiber(void);
#endif
extern void func_file(void);
extern void func_format_msg(void);
#if 0
extern void func_generated(void);
#endif
extern void func_heap(void);
#if 0
extern void func_loader(void);
#endif
extern void func_locale(void);
#if 0
extern void func_mailslot(void);
#endif
extern void func_module(void);
extern void func_path(void);
#if 0
extern void func_pipe(void);
extern void func_process(void);
extern void func_profile(void);
extern void func_resource(void);
#endif
extern void func_sync(void);
extern void func_thread(void);
extern void func_time(void);
#if 0
extern void func_timer(void);
extern void func_toolhelp(void);
#endif
extern void func_version(void);
extern void func_virtual(void);
#if 0
extern void func_volume(void);
#endif

const struct test winetest_testlist[] =
{
#if 0
    { "actctx", func_actctx },
    { "atom", func_atom },
    { "change", func_change },
#endif
    { "codepage", func_codepage },
#if 0
    { "comm", func_comm },
    { "console", func_console },
    { "debugger", func_debugger },
    { "directory", func_directory },
    { "drive", func_drive },
#endif
    { "environ", func_environ },
#if 0
    { "fiber", func_fiber },
#endif
    { "file", func_file },
    { "format_msg", func_format_msg },
#if 0
    { "generated", func_generated },
#endif
    { "heap", func_heap },
#if 0
    { "loader", func_loader },
#endif
    { "locale", func_locale },
#if 0
    { "mailslot", func_mailslot },
#endif
    { "module", func_module },
    { "path", func_path },
#if 0
    { "pipe", func_pipe },
    { "process", func_process },
    { "profile", func_profile },
    { "resource", func_resource },
#endif
    { "sync", func_sync },
    { "thread", func_thread },
    { "time", func_time },
#if 0
    { "timer", func_timer },
    { "toolhelp", func_toolhelp },
#endif
    { "version", func_version },
    { "virtual", func_virtual },
#if 0
    { "volume", func_volume },
#endif
    { 0, 0 }
};
