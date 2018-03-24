#include "config.h"

#include "windef.h"
#include "winbase.h"
#include "winternl.h"

WINBASEAPI void WINAPI DeleteCriticalSection(CRITICAL_SECTION *lpCrit)
{
    RtlDeleteCriticalSection( lpCrit );
}

WINBASEAPI void WINAPI EnterCriticalSection(CRITICAL_SECTION *lpCrit)
{
    RtlEnterCriticalSection( lpCrit );
}

WINBASEAPI void WINAPI LeaveCriticalSection(CRITICAL_SECTION *lpCrit)
{
    RtlLeaveCriticalSection( lpCrit);
}

WINBASEAPI BOOL WINAPI TryEnterCriticalSection(CRITICAL_SECTION *lpCrit)
{
    return RtlTryEnterCriticalSection( lpCrit);
}
