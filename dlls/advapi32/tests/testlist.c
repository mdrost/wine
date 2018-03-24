#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define STANDALONE
#include "wine/test.h"

#if 0
extern void func_cred(void);
#endif
extern void func_crypt(void);
#if 0
extern void func_crypt_lmhash(void);
extern void func_crypt_md4(void);
extern void func_crypt_md5(void);
extern void func_crypt_sha(void);
extern void func_eventlog(void);
extern void func_lsa(void);
extern void func_registry(void);
extern void func_security(void);
extern void func_service(void);
#endif

const struct test winetest_testlist[] =
{
#if 0
    { "cred", func_cred },
#endif
    { "crypt", func_crypt },
#if 0
    { "crypt_lmhash", func_crypt_lmhash },
    { "crypt_md4", func_crypt_md4 },
    { "crypt_md5", func_crypt_md5 },
    { "crypt_sha", func_crypt_sha },
    { "eventlog", func_eventlog },
    { "lsa", func_lsa },
    { "registry", func_registry },
    { "security", func_security },
    { "service", func_service },
#endif
    { 0, 0 }
};
