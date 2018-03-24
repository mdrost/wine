/*
 * Win32 heap functions
 *
 * Copyright 1995, 1996 Alexandre Julliard
 * Copyright 1996 Huw Davies
 * Copyright 1998 Ulrich Weigand
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

#include "config.h"
#include "wine/port.h"

#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef HAVE_MACH_MACH_H
#include <mach/mach.h>
#endif

#ifdef sun
/* FIXME:  Unfortunately swapctl can't be used with largefile.... */
# undef _FILE_OFFSET_BITS
# define _FILE_OFFSET_BITS 32
# ifdef HAVE_SYS_RESOURCE_H
#  include <sys/resource.h>
# endif
# ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
# endif
# include <sys/swap.h>
#endif

#ifdef HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#else
#define RUNNING_ON_VALGRIND 0
#endif

#include "ntstatus.h"
#define WIN32_NO_STATUS
#define NONAMELESSUNION
#include "windef.h"
#include "winbase.h"
#include "winerror.h"
#include "winnt.h"
#include "winternl.h"
#include "wine/exception.h"
#include "wine/list.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(heap);
WINE_DECLARE_DEBUG_CHANNEL(globalmem);

#if 0
/* address where we try to map the system heap */
#define SYSTEM_HEAP_BASE  ((void*)0x80000000)
#endif
#define SYSTEM_HEAP_SIZE  0x1000000   /* Default heap size = 16Mb */

static HANDLE systemHeap;   /* globally shared heap */

#if defined(__i386__) || defined(__x86_64__)
static const UINT_PTR page_size = 0x1000;
#else
extern UINT_PTR page_size DECLSPEC_HIDDEN;
#endif

/* Note: the heap data structures are loosely based on what Pietrek describes in his
 * book 'Windows 95 System Programming Secrets', with some adaptations for
 * better compatibility with NT.
 */

typedef struct tagARENA_INUSE
{
    DWORD  size;                    /* Block size; must be the first field */
    DWORD  magic : 24;              /* Magic number */
    DWORD  unused_bytes : 8;        /* Number of bytes in the block not used by user data (max value is HEAP_MIN_DATA_SIZE+HEAP_MIN_SHRINK_SIZE) */
} ARENA_INUSE;

typedef struct tagARENA_FREE
{
    DWORD                 size;     /* Block size; must be the first field */
    DWORD                 magic;    /* Magic number */
    struct list           entry;    /* Entry in free list */
} ARENA_FREE;

typedef struct
{
    struct list           entry;      /* entry in heap large blocks list */
    SIZE_T                data_size;  /* size of user data */
    SIZE_T                block_size; /* total size of virtual memory block */
    DWORD                 pad[2];     /* padding to ensure 16-byte alignment of data */
    DWORD                 size;       /* fields for compatibility with normal arenas */
    DWORD                 magic;      /* these must remain at the end of the structure */
} ARENA_LARGE;

#define ARENA_FLAG_FREE        0x00000001  /* flags OR'ed with arena size */
#define ARENA_FLAG_PREV_FREE   0x00000002
#define ARENA_SIZE_MASK        (~3)
#define ARENA_LARGE_SIZE       0xfedcba90  /* magic value for 'size' field in large blocks */

/* Value for arena 'magic' field */
#define ARENA_INUSE_MAGIC      0x455355
#define ARENA_PENDING_MAGIC    0xbedead
#define ARENA_FREE_MAGIC       0x45455246
#define ARENA_LARGE_MAGIC      0x6752614c

#define ARENA_INUSE_FILLER     0x55
#define ARENA_TAIL_FILLER      0xab
#define ARENA_FREE_FILLER      0xfeeefeee

/* everything is aligned on 8 byte boundaries (16 for Win64) */
#define ALIGNMENT              (2*sizeof(void*))
#define LARGE_ALIGNMENT        16  /* large blocks have stricter alignment */
#define ARENA_OFFSET           (ALIGNMENT - sizeof(ARENA_INUSE))

C_ASSERT( sizeof(ARENA_LARGE) % LARGE_ALIGNMENT == 0 );

#define ROUND_SIZE(size)       ((((size) + ALIGNMENT - 1) & ~(ALIGNMENT-1)) + ARENA_OFFSET)

#define QUIET                  1           /* Suppress messages  */
#define NOISY                  0           /* Report all errors  */

/* minimum data size (without arenas) of an allocated block */
/* make sure that it's larger than a free list entry */
#define HEAP_MIN_DATA_SIZE    ROUND_SIZE(2 * sizeof(struct list))
#define HEAP_MIN_ARENA_SIZE   (HEAP_MIN_DATA_SIZE + sizeof(ARENA_INUSE))
/* minimum size that must remain to shrink an allocated block */
#define HEAP_MIN_SHRINK_SIZE  (HEAP_MIN_DATA_SIZE+sizeof(ARENA_FREE))
/* minimum size to start allocating large blocks */
#define HEAP_MIN_LARGE_BLOCK_SIZE  0x7f000
/* extra size to add at the end of block for tail checking */
#define HEAP_TAIL_EXTRA_SIZE(flags) \
    ((flags & HEAP_TAIL_CHECKING_ENABLED) || RUNNING_ON_VALGRIND ? ALIGNMENT : 0)

/* There will be a free list bucket for every arena size up to and including this value */
#define HEAP_MAX_SMALL_FREE_LIST 0x100
C_ASSERT( HEAP_MAX_SMALL_FREE_LIST % ALIGNMENT == 0 );
#define HEAP_NB_SMALL_FREE_LISTS (((HEAP_MAX_SMALL_FREE_LIST - HEAP_MIN_ARENA_SIZE) / ALIGNMENT) + 1)

/* Max size of the blocks on the free lists above HEAP_MAX_SMALL_FREE_LIST */
static const SIZE_T HEAP_freeListSizes[] =
{
    0x200, 0x400, 0x1000, ~0UL
};
#define HEAP_NB_FREE_LISTS (sizeof(HEAP_freeListSizes) / sizeof(HEAP_freeListSizes[0]) + HEAP_NB_SMALL_FREE_LISTS)

typedef union
{
    ARENA_FREE  arena;
    void       *alignment[4];
} FREE_LIST_ENTRY;

struct tagHEAP;

typedef struct tagSUBHEAP
{
    void               *base;       /* Base address of the sub-heap memory block */
    SIZE_T              size;       /* Size of the whole sub-heap */
    SIZE_T              min_commit; /* Minimum committed size */
    SIZE_T              commitSize; /* Committed size of the sub-heap */
    struct list         entry;      /* Entry in sub-heap list */
    struct tagHEAP     *heap;       /* Main heap structure */
    DWORD               headerSize; /* Size of the heap header */
    DWORD               magic;      /* Magic number */
} SUBHEAP;

#define SUBHEAP_MAGIC    ((DWORD)('S' | ('U'<<8) | ('B'<<16) | ('H'<<24)))

typedef struct tagHEAP
{
    DWORD_PTR        unknown1[2];
    DWORD            unknown2;
    DWORD            flags;         /* Heap flags */
    DWORD            force_flags;   /* Forced heap flags for debugging */
    SUBHEAP          subheap;       /* First sub-heap */
    struct list      entry;         /* Entry in process heap list */
    struct list      subheap_list;  /* Sub-heap list */
    struct list      large_list;    /* Large blocks list */
    SIZE_T           grow_size;     /* Size of next subheap for growing heap */
    DWORD            magic;         /* Magic number */
    DWORD            pending_pos;   /* Position in pending free requests ring */
    ARENA_INUSE    **pending_free;  /* Ring buffer for pending free requests */
    RTL_CRITICAL_SECTION critSection; /* Critical section for serialization */
    FREE_LIST_ENTRY *freeList;      /* Free lists */
} HEAP;

#define HEAP_MAGIC       ((DWORD)('H' | ('E'<<8) | ('A'<<16) | ('P'<<24)))

#define HEAP_DEF_SIZE        0x110000   /* Default heap size = 1Mb + 64Kb */
#define COMMIT_MASK          0xffff  /* bitmask for commit/decommit granularity */
#define MAX_FREE_PENDING     1024    /* max number of free requests to delay */

/* some undocumented flags (names are made up) */
#define HEAP_PAGE_ALLOCS      0x01000000
#define HEAP_VALIDATE         0x10000000
#define HEAP_VALIDATE_ALL     0x20000000
#define HEAP_VALIDATE_PARAMS  0x40000000

static HEAP *processHeap;  /* main process heap */

static BOOL HEAP_IsRealArena( HEAP *heapPtr, DWORD flags, LPCVOID block, BOOL quiet );

/* mark a block of memory as free for debugging purposes */
static inline void mark_block_free( void *ptr, SIZE_T size, DWORD flags )
{
    if (flags & HEAP_FREE_CHECKING_ENABLED)
    {
        SIZE_T i;
        for (i = 0; i < size / sizeof(DWORD); i++) ((DWORD *)ptr)[i] = ARENA_FREE_FILLER;
    }
#if defined(VALGRIND_MAKE_MEM_NOACCESS)
    VALGRIND_DISCARD( VALGRIND_MAKE_MEM_NOACCESS( ptr, size ));
#elif defined( VALGRIND_MAKE_NOACCESS)
    VALGRIND_DISCARD( VALGRIND_MAKE_NOACCESS( ptr, size ));
#endif
}

/* mark a block of memory as initialized for debugging purposes */
static inline void mark_block_initialized( void *ptr, SIZE_T size )
{
#if defined(VALGRIND_MAKE_MEM_DEFINED)
    VALGRIND_DISCARD( VALGRIND_MAKE_MEM_DEFINED( ptr, size ));
#elif defined(VALGRIND_MAKE_READABLE)
    VALGRIND_DISCARD( VALGRIND_MAKE_READABLE( ptr, size ));
#endif
}

/* mark a block of memory as uninitialized for debugging purposes */
static inline void mark_block_uninitialized( void *ptr, SIZE_T size )
{
#if defined(VALGRIND_MAKE_MEM_UNDEFINED)
    VALGRIND_DISCARD( VALGRIND_MAKE_MEM_UNDEFINED( ptr, size ));
#elif defined(VALGRIND_MAKE_WRITABLE)
    VALGRIND_DISCARD( VALGRIND_MAKE_WRITABLE( ptr, size ));
#endif
}

/* mark a block of memory as a tail block */
static inline void mark_block_tail( void *ptr, SIZE_T size, DWORD flags )
{
    if (flags & HEAP_TAIL_CHECKING_ENABLED)
    {
        mark_block_uninitialized( ptr, size );
        memset( ptr, ARENA_TAIL_FILLER, size );
    }
#if defined(VALGRIND_MAKE_MEM_NOACCESS)
    VALGRIND_DISCARD( VALGRIND_MAKE_MEM_NOACCESS( ptr, size ));
#elif defined( VALGRIND_MAKE_NOACCESS)
    VALGRIND_DISCARD( VALGRIND_MAKE_NOACCESS( ptr, size ));
#endif
}

/* initialize contents of a newly created block of memory */
static inline void initialize_block( void *ptr, SIZE_T size, SIZE_T unused, DWORD flags )
{
    if (flags & HEAP_ZERO_MEMORY)
    {
        mark_block_initialized( ptr, size );
        memset( ptr, 0, size );
    }
    else
    {
        mark_block_uninitialized( ptr, size );
        if (flags & HEAP_FREE_CHECKING_ENABLED)
        {
            memset( ptr, ARENA_INUSE_FILLER, size );
            mark_block_uninitialized( ptr, size );
        }
    }

    mark_block_tail( (char *)ptr + size, unused, flags );
}

/* notify that a new block of memory has been allocated for debugging purposes */
static inline void notify_alloc( void *ptr, SIZE_T size, BOOL init )
{
#ifdef VALGRIND_MALLOCLIKE_BLOCK
    VALGRIND_MALLOCLIKE_BLOCK( ptr, size, 0, init );
#endif
}

/* notify that a block of memory has been freed for debugging purposes */
static inline void notify_free( void const *ptr )
{
#ifdef VALGRIND_FREELIKE_BLOCK
    VALGRIND_FREELIKE_BLOCK( ptr, 0 );
#endif
}

static inline void notify_realloc( void const *ptr, SIZE_T size_old, SIZE_T size_new )
{
#ifdef VALGRIND_RESIZEINPLACE_BLOCK
    /* zero is not a valid size */
    VALGRIND_RESIZEINPLACE_BLOCK( ptr, size_old ? size_old : 1, size_new ? size_new : 1, 0 );
#endif
}

static void subheap_notify_free_all(SUBHEAP const *subheap)
{
#ifdef VALGRIND_FREELIKE_BLOCK
    char const *ptr = (char const *)subheap->base + subheap->headerSize;

    if (!RUNNING_ON_VALGRIND) return;

    while (ptr < (char const *)subheap->base + subheap->size)
    {
        if (*(const DWORD *)ptr & ARENA_FLAG_FREE)
        {
            ARENA_FREE const *pArena = (ARENA_FREE const *)ptr;
            if (pArena->magic!=ARENA_FREE_MAGIC) ERR("bad free_magic @%p\n", pArena);
            ptr += sizeof(*pArena) + (pArena->size & ARENA_SIZE_MASK);
        }
        else
        {
            ARENA_INUSE const *pArena = (ARENA_INUSE const *)ptr;
            if (pArena->magic == ARENA_INUSE_MAGIC) notify_free(pArena + 1);
            else if (pArena->magic != ARENA_PENDING_MAGIC) ERR("bad inuse_magic @%p\n", pArena);
            ptr += sizeof(*pArena) + (pArena->size & ARENA_SIZE_MASK);
        }
    }
#endif
}

/* locate a free list entry of the appropriate size */
/* size is the size of the whole block including the arena header */
static inline unsigned int get_freelist_index( SIZE_T size )
{
    unsigned int i;

    if (size <= HEAP_MAX_SMALL_FREE_LIST)
        return (size - HEAP_MIN_ARENA_SIZE) / ALIGNMENT;

    for (i = HEAP_NB_SMALL_FREE_LISTS; i < HEAP_NB_FREE_LISTS - 1; i++)
        if (size <= HEAP_freeListSizes[i - HEAP_NB_SMALL_FREE_LISTS]) break;
    return i;
}

/* get the memory protection type to use for a given heap */
static inline ULONG get_protection_type( DWORD flags )
{
    return (flags & HEAP_CREATE_ENABLE_EXECUTE) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
}

static RTL_CRITICAL_SECTION_DEBUG process_heap_critsect_debug =
{
    0, 0, NULL,  /* will be set later */
    { &process_heap_critsect_debug.ProcessLocksList, &process_heap_critsect_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": main process heap section") }
};


/***********************************************************************
 *           HEAP_Dump
 */
static void HEAP_Dump( HEAP *heap )
{
    unsigned int i;
    SUBHEAP *subheap;
    char *ptr;

    DPRINTF( "Heap: %p\n", heap );
    DPRINTF( "Next: %p  Sub-heaps:", LIST_ENTRY( heap->entry.next, HEAP, entry ) );
    LIST_FOR_EACH_ENTRY( subheap, &heap->subheap_list, SUBHEAP, entry ) DPRINTF( " %p", subheap );

    DPRINTF( "\nFree lists:\n Block   Stat   Size    Id\n" );
    for (i = 0; i < HEAP_NB_FREE_LISTS; i++)
        DPRINTF( "%p free %08lx prev=%p next=%p\n",
                 &heap->freeList[i].arena, i < HEAP_NB_SMALL_FREE_LISTS ?
                 HEAP_MIN_ARENA_SIZE + i * ALIGNMENT : HEAP_freeListSizes[i - HEAP_NB_SMALL_FREE_LISTS],
                 LIST_ENTRY( heap->freeList[i].arena.entry.prev, ARENA_FREE, entry ),
                 LIST_ENTRY( heap->freeList[i].arena.entry.next, ARENA_FREE, entry ));

    LIST_FOR_EACH_ENTRY( subheap, &heap->subheap_list, SUBHEAP, entry )
    {
        SIZE_T freeSize = 0, usedSize = 0, arenaSize = subheap->headerSize;
        DPRINTF( "\n\nSub-heap %p: base=%p size=%08lx committed=%08lx\n",
                 subheap, subheap->base, subheap->size, subheap->commitSize );

        DPRINTF( "\n Block    Arena   Stat   Size    Id\n" );
        ptr = (char *)subheap->base + subheap->headerSize;
        while (ptr < (char *)subheap->base + subheap->size)
        {
            if (*(DWORD *)ptr & ARENA_FLAG_FREE)
            {
                ARENA_FREE *pArena = (ARENA_FREE *)ptr;
                DPRINTF( "%p %08x free %08x prev=%p next=%p\n",
                         pArena, pArena->magic,
                         pArena->size & ARENA_SIZE_MASK,
                         LIST_ENTRY( pArena->entry.prev, ARENA_FREE, entry ),
                         LIST_ENTRY( pArena->entry.next, ARENA_FREE, entry ) );
                ptr += sizeof(*pArena) + (pArena->size & ARENA_SIZE_MASK);
                arenaSize += sizeof(ARENA_FREE);
                freeSize += pArena->size & ARENA_SIZE_MASK;
            }
            else if (*(DWORD *)ptr & ARENA_FLAG_PREV_FREE)
            {
                ARENA_INUSE *pArena = (ARENA_INUSE *)ptr;
                DPRINTF( "%p %08x Used %08x back=%p\n",
                        pArena, pArena->magic, pArena->size & ARENA_SIZE_MASK, *((ARENA_FREE **)pArena - 1) );
                ptr += sizeof(*pArena) + (pArena->size & ARENA_SIZE_MASK);
                arenaSize += sizeof(ARENA_INUSE);
                usedSize += pArena->size & ARENA_SIZE_MASK;
            }
            else
            {
                ARENA_INUSE *pArena = (ARENA_INUSE *)ptr;
                DPRINTF( "%p %08x %s %08x\n",
                         pArena, pArena->magic, pArena->magic == ARENA_INUSE_MAGIC ? "used" : "pend",
                         pArena->size & ARENA_SIZE_MASK );
                ptr += sizeof(*pArena) + (pArena->size & ARENA_SIZE_MASK);
                arenaSize += sizeof(ARENA_INUSE);
                usedSize += pArena->size & ARENA_SIZE_MASK;
            }
        }
        DPRINTF( "\nTotal: Size=%08lx Committed=%08lx Free=%08lx Used=%08lx Arenas=%08lx (%ld%%)\n\n",
	      subheap->size, subheap->commitSize, freeSize, usedSize,
	      arenaSize, (arenaSize * 100) / subheap->size );
    }
}


static void HEAP_DumpEntry( LPPROCESS_HEAP_ENTRY entry )
{
    WORD rem_flags;
    TRACE( "Dumping entry %p\n", entry );
    TRACE( "lpData\t\t: %p\n", entry->lpData );
    TRACE( "cbData\t\t: %08x\n", entry->cbData);
    TRACE( "cbOverhead\t: %08x\n", entry->cbOverhead);
    TRACE( "iRegionIndex\t: %08x\n", entry->iRegionIndex);
    TRACE( "WFlags\t\t: ");
    if (entry->wFlags & PROCESS_HEAP_REGION)
        TRACE( "PROCESS_HEAP_REGION ");
    if (entry->wFlags & PROCESS_HEAP_UNCOMMITTED_RANGE)
        TRACE( "PROCESS_HEAP_UNCOMMITTED_RANGE ");
    if (entry->wFlags & PROCESS_HEAP_ENTRY_BUSY)
        TRACE( "PROCESS_HEAP_ENTRY_BUSY ");
    if (entry->wFlags & PROCESS_HEAP_ENTRY_MOVEABLE)
        TRACE( "PROCESS_HEAP_ENTRY_MOVEABLE ");
    if (entry->wFlags & PROCESS_HEAP_ENTRY_DDESHARE)
        TRACE( "PROCESS_HEAP_ENTRY_DDESHARE ");
    rem_flags = entry->wFlags &
        ~(PROCESS_HEAP_REGION | PROCESS_HEAP_UNCOMMITTED_RANGE |
          PROCESS_HEAP_ENTRY_BUSY | PROCESS_HEAP_ENTRY_MOVEABLE|
          PROCESS_HEAP_ENTRY_DDESHARE);
    if (rem_flags)
        TRACE( "Unknown %08x", rem_flags);
    TRACE( "\n");
    if ((entry->wFlags & PROCESS_HEAP_ENTRY_BUSY )
        && (entry->wFlags & PROCESS_HEAP_ENTRY_MOVEABLE))
    {
        /* Treat as block */
        TRACE( "BLOCK->hMem\t\t:%p\n", entry->u.Block.hMem);
    }
    if (entry->wFlags & PROCESS_HEAP_REGION)
    {
        TRACE( "Region.dwCommittedSize\t:%08x\n",entry->u.Region.dwCommittedSize);
        TRACE( "Region.dwUnCommittedSize\t:%08x\n",entry->u.Region.dwUnCommittedSize);
        TRACE( "Region.lpFirstBlock\t:%p\n",entry->u.Region.lpFirstBlock);
        TRACE( "Region.lpLastBlock\t:%p\n",entry->u.Region.lpLastBlock);
    }
}

/***********************************************************************
 *           HEAP_GetPtr
 * RETURNS
 *	Pointer to the heap
 *	NULL: Failure
 */
static HEAP *HEAP_GetPtr(
             HANDLE heap /* [in] Handle to the heap */
) {
    HEAP *heapPtr = heap;
    if (!heapPtr || (heapPtr->magic != HEAP_MAGIC))
    {
        ERR("Invalid heap %p!\n", heap );
        return NULL;
    }
    if ((heapPtr->flags & HEAP_VALIDATE_ALL) && !HEAP_IsRealArena( heapPtr, 0, NULL, NOISY ))
    {
        if (TRACE_ON(heap))
        {
            HEAP_Dump( heapPtr );
            assert( FALSE );
        }
        return NULL;
    }
    return heapPtr;
}


/***********************************************************************
 *           HEAP_InsertFreeBlock
 *
 * Insert a free block into the free list.
 */
static inline void HEAP_InsertFreeBlock( HEAP *heap, ARENA_FREE *pArena, BOOL last )
{
    FREE_LIST_ENTRY *pEntry = heap->freeList + get_freelist_index( pArena->size + sizeof(*pArena) );
    if (last)
    {
        /* insert at end of free list, i.e. before the next free list entry */
        pEntry++;
        if (pEntry == &heap->freeList[HEAP_NB_FREE_LISTS]) pEntry = heap->freeList;
        list_add_before( &pEntry->arena.entry, &pArena->entry );
    }
    else
    {
        /* insert at head of free list */
        list_add_after( &pEntry->arena.entry, &pArena->entry );
    }
    pArena->size |= ARENA_FLAG_FREE;
}


/***********************************************************************
 *           HEAP_FindSubHeap
 * Find the sub-heap containing a given address.
 *
 * RETURNS
 *	Pointer: Success
 *	NULL: Failure
 */
static SUBHEAP *HEAP_FindSubHeap(
                const HEAP *heap, /* [in] Heap pointer */
                LPCVOID ptr ) /* [in] Address */
{
    SUBHEAP *sub;
    LIST_FOR_EACH_ENTRY( sub, &heap->subheap_list, SUBHEAP, entry )
        if ((ptr >= sub->base) &&
            ((const char *)ptr < (const char *)sub->base + sub->size - sizeof(ARENA_INUSE)))
            return sub;
    return NULL;
}


/***********************************************************************
 *           HEAP_Commit
 *
 * Make sure the heap storage is committed for a given size in the specified arena.
 */
static inline BOOL HEAP_Commit( SUBHEAP *subheap, ARENA_INUSE *pArena, SIZE_T data_size )
{
#if 0
    void *ptr = (char *)(pArena + 1) + data_size + sizeof(ARENA_FREE);
    SIZE_T size = (char *)ptr - (char *)subheap->base;
    size = (size + COMMIT_MASK) & ~COMMIT_MASK;
    if (size > subheap->size) size = subheap->size;
    if (size <= subheap->commitSize) return TRUE;
    size -= subheap->commitSize;
    ptr = (char *)subheap->base + subheap->commitSize;
    if (NtAllocateVirtualMemory( NtCurrentProcess(), &ptr, 0,
                                 &size, MEM_COMMIT, get_protection_type( subheap->heap->flags ) ))
    {
        WARN("Could not commit %08lx bytes at %p for heap %p\n",
                 size, ptr, subheap->heap );
        return FALSE;
    }
    subheap->commitSize += size;
    return TRUE;
#else
    SetLastError( ERROR_CALL_NOT_IMPLEMENTED );
    return FALSE;
#endif
}


/***********************************************************************
 *           HEAP_Decommit
 *
 * If possible, decommit the heap storage from (including) 'ptr'.
 */
static inline BOOL HEAP_Decommit( SUBHEAP *subheap, void *ptr )
{
#if 0
    void *addr;
    SIZE_T decommit_size;
    SIZE_T size = (char *)ptr - (char *)subheap->base;

    /* round to next block and add one full block */
    size = ((size + COMMIT_MASK) & ~COMMIT_MASK) + COMMIT_MASK + 1;
    size = max( size, subheap->min_commit );
    if (size >= subheap->commitSize) return TRUE;
    decommit_size = subheap->commitSize - size;
    addr = (char *)subheap->base + size;

    if (VirtualFreeEx( NtCurrentProcess(), &addr, &decommit_size, MEM_DECOMMIT ))
    {
        WARN("Could not decommit %08lx bytes at %p for heap %p\n",
             decommit_size, (char *)subheap->base + size, subheap->heap );
        return FALSE;
    }
    subheap->commitSize -= decommit_size;
    return TRUE;
#else
    SetLastError( ERROR_CALL_NOT_IMPLEMENTED );
    return FALSE;
#endif
}


/***********************************************************************
 *           HEAP_CreateFreeBlock
 *
 * Create a free block at a specified address. 'size' is the size of the
 * whole block, including the new arena.
 */
static void HEAP_CreateFreeBlock( SUBHEAP *subheap, void *ptr, SIZE_T size )
{
    ARENA_FREE *pFree;
    char *pEnd;
    BOOL last;
    DWORD flags = subheap->heap->flags;

    /* Create a free arena */
    mark_block_uninitialized( ptr, sizeof(ARENA_FREE) );
    pFree = ptr;
    pFree->magic = ARENA_FREE_MAGIC;

    /* If debugging, erase the freed block content */

    pEnd = (char *)ptr + size;
    if (pEnd > (char *)subheap->base + subheap->commitSize)
        pEnd = (char *)subheap->base + subheap->commitSize;
    if (pEnd > (char *)(pFree + 1)) mark_block_free( pFree + 1, pEnd - (char *)(pFree + 1), flags );

    /* Check if next block is free also */

    if (((char *)ptr + size < (char *)subheap->base + subheap->size) &&
        (*(DWORD *)((char *)ptr + size) & ARENA_FLAG_FREE))
    {
        /* Remove the next arena from the free list */
        ARENA_FREE *pNext = (ARENA_FREE *)((char *)ptr + size);
        list_remove( &pNext->entry );
        size += (pNext->size & ARENA_SIZE_MASK) + sizeof(*pNext);
        mark_block_free( pNext, sizeof(ARENA_FREE), flags );
    }

    /* Set the next block PREV_FREE flag and pointer */

    last = ((char *)ptr + size >= (char *)subheap->base + subheap->size);
    if (!last)
    {
        DWORD *pNext = (DWORD *)((char *)ptr + size);
        *pNext |= ARENA_FLAG_PREV_FREE;
        mark_block_initialized( (ARENA_FREE **)pNext - 1, sizeof( ARENA_FREE * ) );
        *((ARENA_FREE **)pNext - 1) = pFree;
    }

    /* Last, insert the new block into the free list */

    pFree->size = size - sizeof(*pFree);
    HEAP_InsertFreeBlock( subheap->heap, pFree, last );
}


/***********************************************************************
 *           HEAP_MakeInUseBlockFree
 *
 * Turn an in-use block into a free block. Can also decommit the end of
 * the heap, and possibly even free the sub-heap altogether.
 */
static void HEAP_MakeInUseBlockFree( SUBHEAP *subheap, ARENA_INUSE *pArena )
{
    HEAP *heap = subheap->heap;
    ARENA_FREE *pFree;
    SIZE_T size;

    if (heap->pending_free)
    {
        ARENA_INUSE *prev = heap->pending_free[heap->pending_pos];
        heap->pending_free[heap->pending_pos] = pArena;
        heap->pending_pos = (heap->pending_pos + 1) % MAX_FREE_PENDING;
        pArena->magic = ARENA_PENDING_MAGIC;
        mark_block_free( pArena + 1, pArena->size & ARENA_SIZE_MASK, heap->flags );
        if (!prev) return;
        pArena = prev;
        subheap = HEAP_FindSubHeap( heap, pArena );
    }

    /* Check if we can merge with previous block */

    size = (pArena->size & ARENA_SIZE_MASK) + sizeof(*pArena);
    if (pArena->size & ARENA_FLAG_PREV_FREE)
    {
        pFree = *((ARENA_FREE **)pArena - 1);
        size += (pFree->size & ARENA_SIZE_MASK) + sizeof(ARENA_FREE);
        /* Remove it from the free list */
        list_remove( &pFree->entry );
    }
    else pFree = (ARENA_FREE *)pArena;

    /* Create a free block */

    HEAP_CreateFreeBlock( subheap, pFree, size );
    size = (pFree->size & ARENA_SIZE_MASK) + sizeof(ARENA_FREE);
    if ((char *)pFree + size < (char *)subheap->base + subheap->size)
        return;  /* Not the last block, so nothing more to do */

    /* Free the whole sub-heap if it's empty and not the original one */

    if (((char *)pFree == (char *)subheap->base + subheap->headerSize) &&
        (subheap != &subheap->heap->subheap))
    {
        void *addr = subheap->base;

        size = 0;
        /* Remove the free block from the list */
        list_remove( &pFree->entry );
        /* Remove the subheap from the list */
        list_remove( &subheap->entry );
        /* Free the memory */
        subheap->magic = 0;
        VirtualFreeEx( NtCurrentProcess(), &addr, &size, MEM_RELEASE );
        return;
    }

    /* Decommit the end of the heap */

    if (!(subheap->heap->flags & HEAP_SHARED)) HEAP_Decommit( subheap, pFree + 1 );
}


/***********************************************************************
 *           HEAP_ShrinkBlock
 *
 * Shrink an in-use block.
 */
static void HEAP_ShrinkBlock(SUBHEAP *subheap, ARENA_INUSE *pArena, SIZE_T size)
{
    if ((pArena->size & ARENA_SIZE_MASK) >= size + HEAP_MIN_SHRINK_SIZE)
    {
        HEAP_CreateFreeBlock( subheap, (char *)(pArena + 1) + size,
                              (pArena->size & ARENA_SIZE_MASK) - size );
	/* assign size plus previous arena flags */
        pArena->size = size | (pArena->size & ~ARENA_SIZE_MASK);
    }
    else
    {
        /* Turn off PREV_FREE flag in next block */
        char *pNext = (char *)(pArena + 1) + (pArena->size & ARENA_SIZE_MASK);
        if (pNext < (char *)subheap->base + subheap->size)
            *(DWORD *)pNext &= ~ARENA_FLAG_PREV_FREE;
    }
}


/***********************************************************************
 *           allocate_large_block
 */
static void *allocate_large_block( HEAP *heap, DWORD flags, SIZE_T size )
{
    ARENA_LARGE *arena;
    SIZE_T block_size = sizeof(*arena) + ROUND_SIZE(size) + HEAP_TAIL_EXTRA_SIZE(flags);
    LPVOID address = NULL;

    if (block_size < size) return NULL;  /* overflow */
#if 0
    if (NtAllocateVirtualMemory( NtCurrentProcess(), &address, 5,
                                 &block_size, MEM_COMMIT, get_protection_type( flags ) ))
#endif
    {
        WARN("Could not allocate block for %08lx bytes\n", size );
        return NULL;
    }
    arena = address;
    arena->data_size = size;
    arena->block_size = block_size;
    arena->size = ARENA_LARGE_SIZE;
    arena->magic = ARENA_LARGE_MAGIC;
    mark_block_tail( (char *)(arena + 1) + size, block_size - sizeof(*arena) - size, flags );
    list_add_tail( &heap->large_list, &arena->entry );
    notify_alloc( arena + 1, size, flags & HEAP_ZERO_MEMORY );
    return arena + 1;
}


/***********************************************************************
 *           free_large_block
 */
static void free_large_block( HEAP *heap, DWORD flags, void *ptr )
{
    ARENA_LARGE *arena = (ARENA_LARGE *)ptr - 1;
    LPVOID address = arena;
    SIZE_T size = 0;

    list_remove( &arena->entry );
    VirtualFreeEx( NtCurrentProcess(), &address, &size, MEM_RELEASE );
}


/***********************************************************************
 *           realloc_large_block
 */
static void *realloc_large_block( HEAP *heap, DWORD flags, void *ptr, SIZE_T size )
{
    ARENA_LARGE *arena = (ARENA_LARGE *)ptr - 1;
    void *new_ptr;

    if (arena->block_size - sizeof(*arena) >= size)
    {
        SIZE_T unused = arena->block_size - sizeof(*arena) - size;

        /* FIXME: we could remap zero-pages instead */
#ifdef VALGRIND_RESIZEINPLACE_BLOCK
        if (RUNNING_ON_VALGRIND)
            notify_realloc( arena + 1, arena->data_size, size );
        else
#endif
        if (size > arena->data_size)
            initialize_block( (char *)ptr + arena->data_size, size - arena->data_size, unused, flags );
        else
            mark_block_tail( (char *)ptr + size, unused, flags );
        arena->data_size = size;
        return ptr;
    }
    if (flags & HEAP_REALLOC_IN_PLACE_ONLY) return NULL;
    if (!(new_ptr = allocate_large_block( heap, flags, size )))
    {
        WARN("Could not allocate block for %08lx bytes\n", size );
        return NULL;
    }
    memcpy( new_ptr, ptr, arena->data_size );
    free_large_block( heap, flags, ptr );
    notify_free( ptr );
    return new_ptr;
}


/***********************************************************************
 *           find_large_block
 */
static ARENA_LARGE *find_large_block( HEAP *heap, const void *ptr )
{
    ARENA_LARGE *arena;

    LIST_FOR_EACH_ENTRY( arena, &heap->large_list, ARENA_LARGE, entry )
        if (ptr == arena + 1) return arena;

    return NULL;
}


/***********************************************************************
 *           validate_large_arena
 */
static BOOL validate_large_arena( HEAP *heap, const ARENA_LARGE *arena, BOOL quiet )
{
    DWORD flags = heap->flags;

    if ((ULONG_PTR)arena % page_size)
    {
        if (quiet == NOISY)
        {
            ERR( "Heap %p: invalid large arena pointer %p\n", heap, arena );
            if (TRACE_ON(heap)) HEAP_Dump( heap );
        }
        else if (WARN_ON(heap))
        {
            WARN( "Heap %p: unaligned arena pointer %p\n", heap, arena );
            if (TRACE_ON(heap)) HEAP_Dump( heap );
        }
        return FALSE;
    }
    if (arena->size != ARENA_LARGE_SIZE || arena->magic != ARENA_LARGE_MAGIC)
    {
        if (quiet == NOISY)
        {
            ERR( "Heap %p: invalid large arena %p values %x/%x\n",
                 heap, arena, arena->size, arena->magic );
            if (TRACE_ON(heap)) HEAP_Dump( heap );
        }
        else if (WARN_ON(heap))
        {
            WARN( "Heap %p: invalid large arena %p values %x/%x\n",
                  heap, arena, arena->size, arena->magic );
            if (TRACE_ON(heap)) HEAP_Dump( heap );
        }
        return FALSE;
    }
    if (arena->data_size > arena->block_size - sizeof(*arena))
    {
        ERR( "Heap %p: invalid large arena %p size %lx/%lx\n",
             heap, arena, arena->data_size, arena->block_size );
        return FALSE;
    }
    if (flags & HEAP_TAIL_CHECKING_ENABLED)
    {
        SIZE_T i, unused = arena->block_size - sizeof(*arena) - arena->data_size;
        const unsigned char *data = (const unsigned char *)(arena + 1) + arena->data_size;

        for (i = 0; i < unused; i++)
        {
            if (data[i] == ARENA_TAIL_FILLER) continue;
            ERR("Heap %p: block %p tail overwritten at %p (byte %lu/%lu == 0x%02x)\n",
                heap, arena + 1, data + i, i, unused, data[i] );
            return FALSE;
        }
    }
    return TRUE;
}


/***********************************************************************
 *           HEAP_CreateSubHeap
 */
static SUBHEAP *HEAP_CreateSubHeap( HEAP *heap, LPVOID address, DWORD flags,
                                    SIZE_T commitSize, SIZE_T totalSize )
{
#if 0
    SUBHEAP *subheap;
    FREE_LIST_ENTRY *pEntry;
    unsigned int i;

    if (!address)
    {
        if (!commitSize) commitSize = COMMIT_MASK + 1;
        totalSize = min( totalSize, 0xffff0000 );  /* don't allow a heap larger than 4Gb */
        if (totalSize < commitSize) totalSize = commitSize;
        if (flags & HEAP_SHARED) commitSize = totalSize;  /* always commit everything in a shared heap */
        commitSize = min( totalSize, (commitSize + COMMIT_MASK) & ~COMMIT_MASK );

        /* allocate the memory block */
        if (NtAllocateVirtualMemory( NtCurrentProcess(), &address, 0, &totalSize,
                                     MEM_RESERVE, get_protection_type( flags ) ))
        {
            WARN("Could not allocate %08lx bytes\n", totalSize );
            return NULL;
        }
        if (NtAllocateVirtualMemory( NtCurrentProcess(), &address, 0,
                                     &commitSize, MEM_COMMIT, get_protection_type( flags ) ))
        {
            WARN("Could not commit %08lx bytes for sub-heap %p\n", commitSize, address );
            return NULL;
        }
    }

    if (heap)
    {
        /* If this is a secondary subheap, insert it into list */

        subheap = address;
        subheap->base       = address;
        subheap->heap       = heap;
        subheap->size       = totalSize;
        subheap->min_commit = 0x10000;
        subheap->commitSize = commitSize;
        subheap->magic      = SUBHEAP_MAGIC;
        subheap->headerSize = ROUND_SIZE( sizeof(SUBHEAP) );
        list_add_head( &heap->subheap_list, &subheap->entry );
    }
    else
    {
        /* If this is a primary subheap, initialize main heap */

        heap = address;
        heap->flags         = flags;
        heap->magic         = HEAP_MAGIC;
        heap->grow_size     = max( HEAP_DEF_SIZE, totalSize );
        list_init( &heap->subheap_list );
        list_init( &heap->large_list );

        subheap = &heap->subheap;
        subheap->base       = address;
        subheap->heap       = heap;
        subheap->size       = totalSize;
        subheap->min_commit = commitSize;
        subheap->commitSize = commitSize;
        subheap->magic      = SUBHEAP_MAGIC;
        subheap->headerSize = ROUND_SIZE( sizeof(HEAP) );
        list_add_head( &heap->subheap_list, &subheap->entry );

        /* Build the free lists */

        heap->freeList = (FREE_LIST_ENTRY *)((char *)heap + subheap->headerSize);
        subheap->headerSize += HEAP_NB_FREE_LISTS * sizeof(FREE_LIST_ENTRY);
        list_init( &heap->freeList[0].arena.entry );
        for (i = 0, pEntry = heap->freeList; i < HEAP_NB_FREE_LISTS; i++, pEntry++)
        {
            pEntry->arena.size = 0 | ARENA_FLAG_FREE;
            pEntry->arena.magic = ARENA_FREE_MAGIC;
            if (i) list_add_after( &pEntry[-1].arena.entry, &pEntry->arena.entry );
        }

        /* Initialize critical section */

        if (!processHeap)  /* do it by hand to avoid memory allocations */
        {
            heap->critSection.DebugInfo      = &process_heap_critsect_debug;
            heap->critSection.LockCount      = -1;
            heap->critSection.RecursionCount = 0;
            heap->critSection.OwningThread   = 0;
            heap->critSection.LockSemaphore  = 0;
            heap->critSection.SpinCount      = 0;
            process_heap_critsect_debug.CriticalSection = &heap->critSection;
        }
        else
        {
            RtlInitializeCriticalSection( &heap->critSection );
            heap->critSection.DebugInfo->Spare[0] = (DWORD_PTR)(__FILE__ ": HEAP.critSection");
        }

        if (flags & HEAP_SHARED)
        {
            /* let's assume that only one thread at a time will try to do this */
            HANDLE sem = heap->critSection.LockSemaphore;
            if (!sem) NtCreateSemaphore( &sem, SEMAPHORE_ALL_ACCESS, NULL, 0, 1 );

            NtDuplicateObject( NtCurrentProcess(), sem, NtCurrentProcess(), &sem, 0, 0,
                               DUP_HANDLE_MAKE_GLOBAL | DUP_HANDLE_SAME_ACCESS | DUP_HANDLE_CLOSE_SOURCE );
            heap->critSection.LockSemaphore = sem;
            RtlFreeHeap( processHeap, 0, heap->critSection.DebugInfo );
            heap->critSection.DebugInfo = NULL;
        }
    }

    /* Create the first free block */

    HEAP_CreateFreeBlock( subheap, (LPBYTE)subheap->base + subheap->headerSize,
                          subheap->size - subheap->headerSize );

    return subheap;
#else
    SetLastError( ERROR_CALL_NOT_IMPLEMENTED );
    return NULL;
#endif
}


/***********************************************************************
 *           HEAP_FindFreeBlock
 *
 * Find a free block at least as large as the requested size, and make sure
 * the requested size is committed.
 */
static ARENA_FREE *HEAP_FindFreeBlock( HEAP *heap, SIZE_T size,
                                       SUBHEAP **ppSubHeap )
{
    SUBHEAP *subheap;
    struct list *ptr;
    SIZE_T total_size;
    FREE_LIST_ENTRY *pEntry = heap->freeList + get_freelist_index( size + sizeof(ARENA_INUSE) );

    /* Find a suitable free list, and in it find a block large enough */

    ptr = &pEntry->arena.entry;
    while ((ptr = list_next( &heap->freeList[0].arena.entry, ptr )))
    {
        ARENA_FREE *pArena = LIST_ENTRY( ptr, ARENA_FREE, entry );
        SIZE_T arena_size = (pArena->size & ARENA_SIZE_MASK) +
                            sizeof(ARENA_FREE) - sizeof(ARENA_INUSE);
        if (arena_size >= size)
        {
            subheap = HEAP_FindSubHeap( heap, pArena );
            if (!HEAP_Commit( subheap, (ARENA_INUSE *)pArena, size )) return NULL;
            *ppSubHeap = subheap;
            return pArena;
        }
    }

    /* If no block was found, attempt to grow the heap */

    if (!(heap->flags & HEAP_GROWABLE))
    {
        WARN("Not enough space in heap %p for %08lx bytes\n", heap, size );
        return NULL;
    }
    /* make sure that we have a big enough size *committed* to fit another
     * last free arena in !
     * So just one heap struct, one first free arena which will eventually
     * get used, and a second free arena that might get assigned all remaining
     * free space in HEAP_ShrinkBlock() */
    total_size = size + ROUND_SIZE(sizeof(SUBHEAP)) + sizeof(ARENA_INUSE) + sizeof(ARENA_FREE);
    if (total_size < size) return NULL;  /* overflow */

    if ((subheap = HEAP_CreateSubHeap( heap, NULL, heap->flags, total_size,
                                       max( heap->grow_size, total_size ) )))
    {
        if (heap->grow_size < 128 * 1024 * 1024) heap->grow_size *= 2;
    }
    else while (!subheap)  /* shrink the grow size again if we are running out of space */
    {
        if (heap->grow_size <= total_size || heap->grow_size <= 4 * 1024 * 1024) return NULL;
        heap->grow_size /= 2;
        subheap = HEAP_CreateSubHeap( heap, NULL, heap->flags, total_size,
                                      max( heap->grow_size, total_size ) );
    }

    TRACE("created new sub-heap %p of %08lx bytes for heap %p\n",
          subheap, subheap->size, heap );

    *ppSubHeap = subheap;
    return (ARENA_FREE *)((char *)subheap->base + subheap->headerSize);
}


/***********************************************************************
 *           HEAP_IsValidArenaPtr
 *
 * Check that the pointer is inside the range possible for arenas.
 */
static BOOL HEAP_IsValidArenaPtr( const HEAP *heap, const ARENA_FREE *ptr )
{
    unsigned int i;
    const SUBHEAP *subheap = HEAP_FindSubHeap( heap, ptr );
    if (!subheap) return FALSE;
    if ((const char *)ptr >= (const char *)subheap->base + subheap->headerSize) return TRUE;
    if (subheap != &heap->subheap) return FALSE;
    for (i = 0; i < HEAP_NB_FREE_LISTS; i++)
        if (ptr == &heap->freeList[i].arena) return TRUE;
    return FALSE;
}


/***********************************************************************
 *           HEAP_ValidateFreeArena
 */
static BOOL HEAP_ValidateFreeArena( SUBHEAP *subheap, ARENA_FREE *pArena )
{
    DWORD flags = subheap->heap->flags;
    SIZE_T size;
    ARENA_FREE *prev, *next;
    char *heapEnd = (char *)subheap->base + subheap->size;

    /* Check for unaligned pointers */
    if ((ULONG_PTR)pArena % ALIGNMENT != ARENA_OFFSET)
    {
        ERR("Heap %p: unaligned arena pointer %p\n", subheap->heap, pArena );
        return FALSE;
    }

    /* Check magic number */
    if (pArena->magic != ARENA_FREE_MAGIC)
    {
        ERR("Heap %p: invalid free arena magic %08x for %p\n", subheap->heap, pArena->magic, pArena );
        return FALSE;
    }
    /* Check size flags */
    if (!(pArena->size & ARENA_FLAG_FREE) ||
        (pArena->size & ARENA_FLAG_PREV_FREE))
    {
        ERR("Heap %p: bad flags %08x for free arena %p\n",
            subheap->heap, pArena->size & ~ARENA_SIZE_MASK, pArena );
        return FALSE;
    }
    /* Check arena size */
    size = pArena->size & ARENA_SIZE_MASK;
    if ((char *)(pArena + 1) + size > heapEnd)
    {
        ERR("Heap %p: bad size %08lx for free arena %p\n", subheap->heap, size, pArena );
        return FALSE;
    }
    /* Check that next pointer is valid */
    next = LIST_ENTRY( pArena->entry.next, ARENA_FREE, entry );
    if (!HEAP_IsValidArenaPtr( subheap->heap, next ))
    {
        ERR("Heap %p: bad next ptr %p for arena %p\n",
            subheap->heap, next, pArena );
        return FALSE;
    }
    /* Check that next arena is free */
    if (!(next->size & ARENA_FLAG_FREE) || (next->magic != ARENA_FREE_MAGIC))
    {
        ERR("Heap %p: next arena %p invalid for %p\n",
            subheap->heap, next, pArena );
        return FALSE;
    }
    /* Check that prev pointer is valid */
    prev = LIST_ENTRY( pArena->entry.prev, ARENA_FREE, entry );
    if (!HEAP_IsValidArenaPtr( subheap->heap, prev ))
    {
        ERR("Heap %p: bad prev ptr %p for arena %p\n",
            subheap->heap, prev, pArena );
        return FALSE;
    }
    /* Check that prev arena is free */
    if (!(prev->size & ARENA_FLAG_FREE) || (prev->magic != ARENA_FREE_MAGIC))
    {
	/* this often means that the prev arena got overwritten
	 * by a memory write before that prev arena */
        ERR("Heap %p: prev arena %p invalid for %p\n",
            subheap->heap, prev, pArena );
        return FALSE;
    }
    /* Check that next block has PREV_FREE flag */
    if ((char *)(pArena + 1) + size < heapEnd)
    {
        if (!(*(DWORD *)((char *)(pArena + 1) + size) & ARENA_FLAG_PREV_FREE))
        {
            ERR("Heap %p: free arena %p next block has no PREV_FREE flag\n",
                subheap->heap, pArena );
            return FALSE;
        }
        /* Check next block back pointer */
        if (*((ARENA_FREE **)((char *)(pArena + 1) + size) - 1) != pArena)
        {
            ERR("Heap %p: arena %p has wrong back ptr %p\n",
                subheap->heap, pArena,
                *((ARENA_FREE **)((char *)(pArena+1) + size) - 1));
            return FALSE;
        }
    }
    if (flags & HEAP_FREE_CHECKING_ENABLED)
    {
        DWORD *ptr = (DWORD *)(pArena + 1);
        char *end = (char *)(pArena + 1) + size;

        if (end >= heapEnd) end = (char *)subheap->base + subheap->commitSize;
        else end -= sizeof(ARENA_FREE *);
        while (ptr < (DWORD *)end)
        {
            if (*ptr != ARENA_FREE_FILLER)
            {
                ERR("Heap %p: free block %p overwritten at %p by %08x\n",
                    subheap->heap, (ARENA_INUSE *)pArena + 1, ptr, *ptr );
                return FALSE;
            }
            ptr++;
        }
    }
    return TRUE;
}


/***********************************************************************
 *           HEAP_ValidateInUseArena
 */
static BOOL HEAP_ValidateInUseArena( const SUBHEAP *subheap, const ARENA_INUSE *pArena, BOOL quiet )
{
    SIZE_T size;
    DWORD i, flags = subheap->heap->flags;
    const char *heapEnd = (const char *)subheap->base + subheap->size;

    /* Check for unaligned pointers */
    if ((ULONG_PTR)pArena % ALIGNMENT != ARENA_OFFSET)
    {
        if ( quiet == NOISY )
        {
            ERR( "Heap %p: unaligned arena pointer %p\n", subheap->heap, pArena );
            if ( TRACE_ON(heap) )
                HEAP_Dump( subheap->heap );
        }
        else if ( WARN_ON(heap) )
        {
            WARN( "Heap %p: unaligned arena pointer %p\n", subheap->heap, pArena );
            if ( TRACE_ON(heap) )
                HEAP_Dump( subheap->heap );
        }
        return FALSE;
    }

    /* Check magic number */
    if (pArena->magic != ARENA_INUSE_MAGIC && pArena->magic != ARENA_PENDING_MAGIC)
    {
        if (quiet == NOISY) {
            ERR("Heap %p: invalid in-use arena magic %08x for %p\n", subheap->heap, pArena->magic, pArena );
            if (TRACE_ON(heap))
               HEAP_Dump( subheap->heap );
        }  else if (WARN_ON(heap)) {
            WARN("Heap %p: invalid in-use arena magic %08x for %p\n", subheap->heap, pArena->magic, pArena );
            if (TRACE_ON(heap))
               HEAP_Dump( subheap->heap );
        }
        return FALSE;
    }
    /* Check size flags */
    if (pArena->size & ARENA_FLAG_FREE)
    {
        ERR("Heap %p: bad flags %08x for in-use arena %p\n",
            subheap->heap, pArena->size & ~ARENA_SIZE_MASK, pArena );
        return FALSE;
    }
    /* Check arena size */
    size = pArena->size & ARENA_SIZE_MASK;
    if ((const char *)(pArena + 1) + size > heapEnd ||
        (const char *)(pArena + 1) + size < (const char *)(pArena + 1))
    {
        ERR("Heap %p: bad size %08lx for in-use arena %p\n", subheap->heap, size, pArena );
        return FALSE;
    }
    /* Check next arena PREV_FREE flag */
    if (((const char *)(pArena + 1) + size < heapEnd) &&
        (*(const DWORD *)((const char *)(pArena + 1) + size) & ARENA_FLAG_PREV_FREE))
    {
        ERR("Heap %p: in-use arena %p next block %p has PREV_FREE flag %x\n",
            subheap->heap, pArena, (const char *)(pArena + 1) + size,*(const DWORD *)((const char *)(pArena + 1) + size) );
        return FALSE;
    }
    /* Check prev free arena */
    if (pArena->size & ARENA_FLAG_PREV_FREE)
    {
        const ARENA_FREE *pPrev = *((const ARENA_FREE * const*)pArena - 1);
        /* Check prev pointer */
        if (!HEAP_IsValidArenaPtr( subheap->heap, pPrev ))
        {
            ERR("Heap %p: bad back ptr %p for arena %p\n",
                subheap->heap, pPrev, pArena );
            return FALSE;
        }
        /* Check that prev arena is free */
        if (!(pPrev->size & ARENA_FLAG_FREE) ||
            (pPrev->magic != ARENA_FREE_MAGIC))
        {
            ERR("Heap %p: prev arena %p invalid for in-use %p\n",
                subheap->heap, pPrev, pArena );
            return FALSE;
        }
        /* Check that prev arena is really the previous block */
        if ((const char *)(pPrev + 1) + (pPrev->size & ARENA_SIZE_MASK) != (const char *)pArena)
        {
            ERR("Heap %p: prev arena %p is not prev for in-use %p\n",
                subheap->heap, pPrev, pArena );
            return FALSE;
        }
    }
    /* Check unused size */
    if (pArena->unused_bytes > size)
    {
        ERR("Heap %p: invalid unused size %08x/%08lx\n", subheap->heap, pArena->unused_bytes, size );
        return FALSE;
    }
    /* Check unused bytes */
    if (pArena->magic == ARENA_PENDING_MAGIC)
    {
        const DWORD *ptr = (const DWORD *)(pArena + 1);
        const DWORD *end = (const DWORD *)((const char *)ptr + size);

        while (ptr < end)
        {
            if (*ptr != ARENA_FREE_FILLER)
            {
                ERR("Heap %p: free block %p overwritten at %p by %08x\n",
                    subheap->heap, (const ARENA_INUSE *)pArena + 1, ptr, *ptr );
#if 0
                if (!*ptr) { HEAP_Dump( subheap->heap ); DbgBreakPoint(); }
#else
                if (!*ptr) { HEAP_Dump( subheap->heap ); DebugBreak(); }
#endif
                return FALSE;
            }
            ptr++;
        }
    }
    else if (flags & HEAP_TAIL_CHECKING_ENABLED)
    {
        const unsigned char *data = (const unsigned char *)(pArena + 1) + size - pArena->unused_bytes;

        for (i = 0; i < pArena->unused_bytes; i++)
        {
            if (data[i] == ARENA_TAIL_FILLER) continue;
            ERR("Heap %p: block %p tail overwritten at %p (byte %u/%u == 0x%02x)\n",
                subheap->heap, pArena + 1, data + i, i, pArena->unused_bytes, data[i] );
            return FALSE;
        }
    }
    return TRUE;
}


/***********************************************************************
 *           HEAP_IsRealArena  [Internal]
 * Validates a block is a valid arena.
 *
 * RETURNS
 *	TRUE: Success
 *	FALSE: Failure
 */
static BOOL HEAP_IsRealArena( HEAP *heapPtr,   /* [in] ptr to the heap */
              DWORD flags,   /* [in] Bit flags that control access during operation */
              LPCVOID block, /* [in] Optional pointer to memory block to validate */
              BOOL quiet )   /* [in] Flag - if true, HEAP_ValidateInUseArena
                              *             does not complain    */
{
    SUBHEAP *subheap;
    BOOL ret = TRUE;
    const ARENA_LARGE *large_arena;

    flags &= HEAP_NO_SERIALIZE;
    flags |= heapPtr->flags;
    /* calling HeapLock may result in infinite recursion, so do the critsect directly */
    if (!(flags & HEAP_NO_SERIALIZE))
        EnterCriticalSection( &heapPtr->critSection );

    if (block)  /* only check this single memory block */
    {
        const ARENA_INUSE *arena = (const ARENA_INUSE *)block - 1;

        if (!(subheap = HEAP_FindSubHeap( heapPtr, arena )) ||
            ((const char *)arena < (char *)subheap->base + subheap->headerSize))
        {
            if (!(large_arena = find_large_block( heapPtr, block )))
            {
                if (quiet == NOISY)
                    ERR("Heap %p: block %p is not inside heap\n", heapPtr, block );
                else if (WARN_ON(heap))
                    WARN("Heap %p: block %p is not inside heap\n", heapPtr, block );
                ret = FALSE;
            }
            else
                ret = validate_large_arena( heapPtr, large_arena, quiet );
        } else
            ret = HEAP_ValidateInUseArena( subheap, arena, quiet );

        if (!(flags & HEAP_NO_SERIALIZE))
            LeaveCriticalSection( &heapPtr->critSection );
        return ret;
    }

    LIST_FOR_EACH_ENTRY( subheap, &heapPtr->subheap_list, SUBHEAP, entry )
    {
        char *ptr = (char *)subheap->base + subheap->headerSize;
        while (ptr < (char *)subheap->base + subheap->size)
        {
            if (*(DWORD *)ptr & ARENA_FLAG_FREE)
            {
                if (!HEAP_ValidateFreeArena( subheap, (ARENA_FREE *)ptr )) {
                    ret = FALSE;
                    break;
                }
                ptr += sizeof(ARENA_FREE) + (*(DWORD *)ptr & ARENA_SIZE_MASK);
            }
            else
            {
                if (!HEAP_ValidateInUseArena( subheap, (ARENA_INUSE *)ptr, NOISY )) {
                    ret = FALSE;
                    break;
                }
                ptr += sizeof(ARENA_INUSE) + (*(DWORD *)ptr & ARENA_SIZE_MASK);
            }
        }
        if (!ret) break;
    }

    LIST_FOR_EACH_ENTRY( large_arena, &heapPtr->large_list, ARENA_LARGE, entry )
        if (!(ret = validate_large_arena( heapPtr, large_arena, quiet ))) break;

    if (!(flags & HEAP_NO_SERIALIZE)) LeaveCriticalSection( &heapPtr->critSection );
    return ret;
}


/***********************************************************************
 *           validate_block_pointer
 *
 * Minimum validation needed to catch bad parameters in heap functions.
 */
static BOOL validate_block_pointer( HEAP *heap, SUBHEAP **ret_subheap, const ARENA_INUSE *arena )
{
    SUBHEAP *subheap;
    BOOL ret = FALSE;

    if (!(*ret_subheap = subheap = HEAP_FindSubHeap( heap, arena )))
    {
        ARENA_LARGE *large_arena = find_large_block( heap, arena + 1 );

        if (!large_arena)
        {
            WARN( "Heap %p: pointer %p is not inside heap\n", heap, arena + 1 );
            return FALSE;
        }
        if ((heap->flags & HEAP_VALIDATE) && !validate_large_arena( heap, large_arena, QUIET ))
            return FALSE;
        return TRUE;
    }

    if ((const char *)arena < (char *)subheap->base + subheap->headerSize)
        WARN( "Heap %p: pointer %p is inside subheap %p header\n", subheap->heap, arena + 1, subheap );
    else if (subheap->heap->flags & HEAP_VALIDATE)  /* do the full validation */
        ret = HEAP_ValidateInUseArena( subheap, arena, QUIET );
    else if ((ULONG_PTR)arena % ALIGNMENT != ARENA_OFFSET)
        WARN( "Heap %p: unaligned arena pointer %p\n", subheap->heap, arena );
    else if (arena->magic == ARENA_PENDING_MAGIC)
        WARN( "Heap %p: block %p used after free\n", subheap->heap, arena + 1 );
    else if (arena->magic != ARENA_INUSE_MAGIC)
        WARN( "Heap %p: invalid in-use arena magic %08x for %p\n", subheap->heap, arena->magic, arena );
    else if (arena->size & ARENA_FLAG_FREE)
        ERR( "Heap %p: bad flags %08x for in-use arena %p\n",
             subheap->heap, arena->size & ~ARENA_SIZE_MASK, arena );
    else if ((const char *)(arena + 1) + (arena->size & ARENA_SIZE_MASK) > (const char *)subheap->base + subheap->size ||
             (const char *)(arena + 1) + (arena->size & ARENA_SIZE_MASK) < (const char *)(arena + 1))
        ERR( "Heap %p: bad size %08x for in-use arena %p\n",
             subheap->heap, arena->size & ARENA_SIZE_MASK, arena );
    else
        ret = TRUE;

    return ret;
}


/***********************************************************************
 *           heap_set_debug_flags
 */
void heap_set_debug_flags( HANDLE handle )
{
    HEAP *heap = HEAP_GetPtr( handle );
    ULONG global_flags = RtlGetNtGlobalFlags();
    ULONG flags = 0;

    if (TRACE_ON(heap)) global_flags |= FLG_HEAP_VALIDATE_ALL;
    if (WARN_ON(heap)) global_flags |= FLG_HEAP_VALIDATE_PARAMETERS;

    if (global_flags & FLG_HEAP_ENABLE_TAIL_CHECK) flags |= HEAP_TAIL_CHECKING_ENABLED;
    if (global_flags & FLG_HEAP_ENABLE_FREE_CHECK) flags |= HEAP_FREE_CHECKING_ENABLED;
    if (global_flags & FLG_HEAP_DISABLE_COALESCING) flags |= HEAP_DISABLE_COALESCE_ON_FREE;
    if (global_flags & FLG_HEAP_PAGE_ALLOCS) flags |= HEAP_PAGE_ALLOCS | HEAP_GROWABLE;

    if (global_flags & FLG_HEAP_VALIDATE_PARAMETERS)
        flags |= HEAP_VALIDATE | HEAP_VALIDATE_PARAMS |
                 HEAP_TAIL_CHECKING_ENABLED | HEAP_FREE_CHECKING_ENABLED;
    if (global_flags & FLG_HEAP_VALIDATE_ALL)
        flags |= HEAP_VALIDATE | HEAP_VALIDATE_ALL |
                 HEAP_TAIL_CHECKING_ENABLED | HEAP_FREE_CHECKING_ENABLED;

    if (RUNNING_ON_VALGRIND) flags = 0; /* no sense in validating since Valgrind catches accesses */

    heap->flags |= flags;
    heap->force_flags |= flags & ~(HEAP_VALIDATE | HEAP_DISABLE_COALESCE_ON_FREE);

    if (flags & (HEAP_FREE_CHECKING_ENABLED | HEAP_TAIL_CHECKING_ENABLED))  /* fix existing blocks */
    {
        SUBHEAP *subheap;
        ARENA_LARGE *large;

        LIST_FOR_EACH_ENTRY( subheap, &heap->subheap_list, SUBHEAP, entry )
        {
            char *ptr = (char *)subheap->base + subheap->headerSize;
            char *end = (char *)subheap->base + subheap->commitSize;
            while (ptr < end)
            {
                ARENA_INUSE *arena = (ARENA_INUSE *)ptr;
                SIZE_T size = arena->size & ARENA_SIZE_MASK;
                if (arena->size & ARENA_FLAG_FREE)
                {
                    SIZE_T count = size;

                    ptr += sizeof(ARENA_FREE) + size;
                    if (ptr >= end) count = end - (char *)((ARENA_FREE *)arena + 1);
                    else count -= sizeof(ARENA_FREE *);
                    mark_block_free( (ARENA_FREE *)arena + 1, count, flags );
                }
                else
                {
                    if (arena->magic == ARENA_PENDING_MAGIC)
                        mark_block_free( arena + 1, size, flags );
                    else
                        mark_block_tail( (char *)(arena + 1) + size - arena->unused_bytes,
                                         arena->unused_bytes, flags );
                    ptr += sizeof(ARENA_INUSE) + size;
                }
            }
        }

        LIST_FOR_EACH_ENTRY( large, &heap->large_list, ARENA_LARGE, entry )
            mark_block_tail( (char *)(large + 1) + large->data_size,
                             large->block_size - sizeof(*large) - large->data_size, flags );
    }

    if ((heap->flags & HEAP_GROWABLE) && !heap->pending_free &&
        ((flags & HEAP_FREE_CHECKING_ENABLED) || RUNNING_ON_VALGRIND))
    {
        void *ptr = NULL;
        SIZE_T size = MAX_FREE_PENDING * sizeof(*heap->pending_free);

#if 0
        if (!NtAllocateVirtualMemory( NtCurrentProcess(), &ptr, 4, &size, MEM_COMMIT, PAGE_READWRITE ))
        {
            heap->pending_free = ptr;
            heap->pending_pos = 0;
        }
#endif
    }
}

/***********************************************************************
 *           RtlCreateHeap   (NTDLL.@)
 *
 * Create a new Heap.
 *
 * PARAMS
 *  flags      [I] HEAP_ flags from "winnt.h"
 *  addr       [I] Desired base address
 *  totalSize  [I] Total size of the heap, or 0 for a growable heap
 *  commitSize [I] Amount of heap space to commit
 *  unknown    [I] Not yet understood
 *  definition [I] Heap definition
 *
 * RETURNS
 *  Success: A HANDLE to the newly created heap.
 *  Failure: a NULL HANDLE.
 */
HANDLE WINAPI HEAP_CreateHeap( ULONG flags, PVOID addr, SIZE_T totalSize, SIZE_T commitSize,
                             PVOID unknown, PRTL_HEAP_DEFINITION definition )
{
    SUBHEAP *subheap;

    /* Allocate the heap block */

    if (!totalSize)
    {
        totalSize = HEAP_DEF_SIZE;
        flags |= HEAP_GROWABLE;
    }

    if (!(subheap = HEAP_CreateSubHeap( NULL, addr, flags, commitSize, totalSize ))) return 0;

    heap_set_debug_flags( subheap->heap );

    /* link it into the per-process heap list */
    if (processHeap)
    {
        HEAP *heapPtr = subheap->heap;
        EnterCriticalSection( &processHeap->critSection );
        list_add_head( &processHeap->entry, &heapPtr->entry );
        LeaveCriticalSection( &processHeap->critSection );
    }
    else if (!addr)
    {
        processHeap = subheap->heap;  /* assume the first heap we create is the process main heap */
        list_init( &processHeap->entry );
    }

    return subheap->heap;
}

/***********************************************************************
 *           HEAP_CreateSystemHeap
 *
 * Create the system heap.
 */
static inline HANDLE HEAP_CreateSystemHeap(void)
{
#if 0
    int created;
    void *base;
    HANDLE map, event;

    /* create the system heap event first */
    event = CreateEventA( NULL, TRUE, FALSE, "__wine_system_heap_event" );

    if (!(map = CreateFileMappingA( INVALID_HANDLE_VALUE, NULL, SEC_COMMIT | PAGE_READWRITE,
                                    0, SYSTEM_HEAP_SIZE, "__wine_system_heap" ))) return 0;
    created = (GetLastError() != ERROR_ALREADY_EXISTS);

    if (!(base = MapViewOfFileEx( map, FILE_MAP_ALL_ACCESS, 0, 0, 0, SYSTEM_HEAP_BASE )))
    {
        /* pre-defined address not available */
        ERR( "system heap base address %p not available\n", SYSTEM_HEAP_BASE );
        return 0;
    }

    if (created)  /* newly created heap */
    {
#if 0
        systemHeap = RtlCreateHeap( HEAP_SHARED, base, SYSTEM_HEAP_SIZE,
                                    SYSTEM_HEAP_SIZE, NULL, NULL );
#else
        systemHeap = HEAP_CreateHeap( HEAP_SHARED, base, SYSTEM_HEAP_SIZE,
                                    SYSTEM_HEAP_SIZE, NULL, NULL );
#endif
        SetEvent( event );
    }
    else
    {
        /* wait for the heap to be initialized */
        WaitForSingleObject( event, INFINITE );
        systemHeap = base;
    }
    CloseHandle( map );
    return systemHeap;
#else
    SetLastError( ERROR_CALL_NOT_IMPLEMENTED );
    return 0;
#endif
}


/***********************************************************************
 *           HeapCreate   (KERNEL32.@)
 *
 * Create a heap object.
 *
 * RETURNS
 *	Handle of heap: Success
 *	NULL: Failure
 */
HANDLE WINAPI HeapCreate(
                DWORD flags,       /* [in] Heap allocation flag */
                SIZE_T initialSize, /* [in] Initial heap size */
                SIZE_T maxSize      /* [in] Maximum heap size */
) {
    HANDLE ret;

    if ( flags & HEAP_SHARED )
    {
        if (!systemHeap) HEAP_CreateSystemHeap();
        else WARN( "Shared Heap requested, returning system heap.\n" );
        ret = systemHeap;
    }
    else
    {
#if 0
        ret = RtlCreateHeap( flags, NULL, maxSize, initialSize, NULL, NULL );
#else
        ret = HEAP_CreateHeap( flags, NULL, maxSize, initialSize, NULL, NULL );
#endif
        if (!ret) SetLastError( ERROR_NOT_ENOUGH_MEMORY );
    }
    return ret;
}


/***********************************************************************
 *           RtlDestroyHeap   (NTDLL.@)
 *
 * Destroy a Heap created with RtlCreateHeap().
 *
 * PARAMS
 *  heap [I] Heap to destroy.
 *
 * RETURNS
 *  Success: A NULL HANDLE, if heap is NULL or it was destroyed
 *  Failure: The Heap handle, if heap is the process heap.
 */
static HANDLE WINAPI HEAP_DestroyHeap( HANDLE heap )
{
    HEAP *heapPtr = HEAP_GetPtr( heap );
    SUBHEAP *subheap, *next;
    ARENA_LARGE *arena, *arena_next;
    SIZE_T size;
    void *addr;

    TRACE("%p\n", heap );
    if (!heapPtr) return heap;

    if (heap == processHeap) return heap; /* cannot delete the main process heap */

    /* remove it from the per-process list */
    EnterCriticalSection( &processHeap->critSection );
    list_remove( &heapPtr->entry );
    LeaveCriticalSection( &processHeap->critSection );

    heapPtr->critSection.DebugInfo->Spare[0] = 0;
    DeleteCriticalSection( &heapPtr->critSection );

    LIST_FOR_EACH_ENTRY_SAFE( arena, arena_next, &heapPtr->large_list, ARENA_LARGE, entry )
    {
        list_remove( &arena->entry );
        size = 0;
        addr = arena;
        VirtualFreeEx( NtCurrentProcess(), &addr, &size, MEM_RELEASE );
    }
    LIST_FOR_EACH_ENTRY_SAFE( subheap, next, &heapPtr->subheap_list, SUBHEAP, entry )
    {
        if (subheap == &heapPtr->subheap) continue;  /* do this one last */
        subheap_notify_free_all(subheap);
        list_remove( &subheap->entry );
        size = 0;
        addr = subheap->base;
        VirtualFreeEx( NtCurrentProcess(), &addr, &size, MEM_RELEASE );
    }
    subheap_notify_free_all(&heapPtr->subheap);
    if (heapPtr->pending_free)
    {
        size = 0;
        addr = heapPtr->pending_free;
        VirtualFreeEx( NtCurrentProcess(), &addr, &size, MEM_RELEASE );
    }
    size = 0;
    addr = heapPtr->subheap.base;
    VirtualFreeEx( NtCurrentProcess(), &addr, &size, MEM_RELEASE );
    return 0;
}


/***********************************************************************
 *           HeapDestroy   (KERNEL32.@)
 *
 * Destroy a heap object.
 *
 * RETURNS
 *	TRUE: Success
 *	FALSE: Failure
 */
BOOL WINAPI HeapDestroy( HANDLE heap /* [in] Handle of heap */ )
{
    if (heap == systemHeap)
    {
        WARN( "attempt to destroy system heap, returning TRUE!\n" );
        return TRUE;
    }
#if 0
    if (!RtlDestroyHeap( heap )) return TRUE;
#else
    if (!HEAP_DestroyHeap( heap )) return TRUE;
#endif
    SetLastError( ERROR_INVALID_HANDLE );
    return FALSE;
}


/***********************************************************************
 *           HeapCompact   (KERNEL32.@)
 */
SIZE_T WINAPI HeapCompact( HANDLE heap, DWORD flags )
{
#if 0
    return RtlCompactHeap( heap, flags );
#else
    static BOOL reported;
    if (!reported++) FIXME( "(%p, 0x%x) stub\n", heap, flags );
    return 0;
#endif
}


/***********************************************************************
 *           HeapValidate   (KERNEL32.@)
 * Validates a specified heap.
 *
 * NOTES
 *	Flags is ignored.
 *
 * RETURNS
 *	TRUE: Success
 *	FALSE: Failure
 */
BOOL WINAPI HeapValidate(
              HANDLE heap, /* [in] Handle to the heap */
              DWORD flags,   /* [in] Bit flags that control access during operation */
              LPCVOID block  /* [in] Optional pointer to memory block to validate */
) {
#if 0
    return RtlValidateHeap( heap, flags, block );
#else
    HEAP *heapPtr = HEAP_GetPtr( heap );
    if (!heapPtr) return FALSE;
    return HEAP_IsRealArena( heapPtr, flags, block, QUIET );
#endif
}


/***********************************************************************
 *           RtlWalkHeap    (NTDLL.@)
 *
 * FIXME
 *  The PROCESS_HEAP_ENTRY flag values seem different between this
 *  function and HeapWalk(). To be checked.
 */
NTSTATUS WINAPI HEAP_WalkHeap( HANDLE heap, PVOID entry_ptr )
{
    LPPROCESS_HEAP_ENTRY entry = entry_ptr; /* FIXME */
    HEAP *heapPtr = HEAP_GetPtr(heap);
    SUBHEAP *sub, *currentheap = NULL;
    NTSTATUS ret;
    char *ptr;
    int region_index = 0;

    if (!heapPtr || !entry) return STATUS_INVALID_PARAMETER;

    if (!(heapPtr->flags & HEAP_NO_SERIALIZE)) EnterCriticalSection( &heapPtr->critSection );

    /* FIXME: enumerate large blocks too */

    /* set ptr to the next arena to be examined */

    if (!entry->lpData) /* first call (init) ? */
    {
        TRACE("begin walking of heap %p.\n", heap);
        currentheap = &heapPtr->subheap;
        ptr = (char*)currentheap->base + currentheap->headerSize;
    }
    else
    {
        ptr = entry->lpData;
        LIST_FOR_EACH_ENTRY( sub, &heapPtr->subheap_list, SUBHEAP, entry )
        {
            if ((ptr >= (char *)sub->base) &&
                (ptr < (char *)sub->base + sub->size))
            {
                currentheap = sub;
                break;
            }
            region_index++;
        }
        if (currentheap == NULL)
        {
            ERR("no matching subheap found, shouldn't happen !\n");
            ret = STATUS_NO_MORE_ENTRIES;
            goto HW_end;
        }

        if (((ARENA_INUSE *)ptr - 1)->magic == ARENA_INUSE_MAGIC ||
            ((ARENA_INUSE *)ptr - 1)->magic == ARENA_PENDING_MAGIC)
        {
            ARENA_INUSE *pArena = (ARENA_INUSE *)ptr - 1;
            ptr += pArena->size & ARENA_SIZE_MASK;
        }
        else if (((ARENA_FREE *)ptr - 1)->magic == ARENA_FREE_MAGIC)
        {
            ARENA_FREE *pArena = (ARENA_FREE *)ptr - 1;
            ptr += pArena->size & ARENA_SIZE_MASK;
        }
        else
            ptr += entry->cbData; /* point to next arena */

        if (ptr > (char *)currentheap->base + currentheap->size - 1)
        {   /* proceed with next subheap */
            struct list *next = list_next( &heapPtr->subheap_list, &currentheap->entry );
            if (!next)
            {  /* successfully finished */
                TRACE("end reached.\n");
                ret = STATUS_NO_MORE_ENTRIES;
                goto HW_end;
            }
            currentheap = LIST_ENTRY( next, SUBHEAP, entry );
            ptr = (char *)currentheap->base + currentheap->headerSize;
        }
    }

    entry->wFlags = 0;
    if (*(DWORD *)ptr & ARENA_FLAG_FREE)
    {
        ARENA_FREE *pArena = (ARENA_FREE *)ptr;

        /*TRACE("free, magic: %04x\n", pArena->magic);*/

        entry->lpData = pArena + 1;
        entry->cbData = pArena->size & ARENA_SIZE_MASK;
        entry->cbOverhead = sizeof(ARENA_FREE);
        entry->wFlags = PROCESS_HEAP_UNCOMMITTED_RANGE;
    }
    else
    {
        ARENA_INUSE *pArena = (ARENA_INUSE *)ptr;

        /*TRACE("busy, magic: %04x\n", pArena->magic);*/

        entry->lpData = pArena + 1;
        entry->cbData = pArena->size & ARENA_SIZE_MASK;
        entry->cbOverhead = sizeof(ARENA_INUSE);
        entry->wFlags = (pArena->magic == ARENA_PENDING_MAGIC) ?
                        PROCESS_HEAP_UNCOMMITTED_RANGE : PROCESS_HEAP_ENTRY_BUSY;
        /* FIXME: can't handle PROCESS_HEAP_ENTRY_MOVEABLE
        and PROCESS_HEAP_ENTRY_DDESHARE yet */
    }

    entry->iRegionIndex = region_index;

    /* first element of heap ? */
    if (ptr == (char *)currentheap->base + currentheap->headerSize)
    {
        entry->wFlags |= PROCESS_HEAP_REGION;
        entry->u.Region.dwCommittedSize = currentheap->commitSize;
        entry->u.Region.dwUnCommittedSize =
                currentheap->size - currentheap->commitSize;
        entry->u.Region.lpFirstBlock = /* first valid block */
                (char *)currentheap->base + currentheap->headerSize;
        entry->u.Region.lpLastBlock  = /* first invalid block */
                (char *)currentheap->base + currentheap->size;
    }
    ret = STATUS_SUCCESS;
    if (TRACE_ON(heap)) HEAP_DumpEntry(entry);

HW_end:
    if (!(heapPtr->flags & HEAP_NO_SERIALIZE)) LeaveCriticalSection( &heapPtr->critSection );
    return ret;
}

/***********************************************************************
 *           HeapWalk   (KERNEL32.@)
 * Enumerates the memory blocks in a specified heap.
 *
 * TODO
 *   - handling of PROCESS_HEAP_ENTRY_MOVEABLE and
 *     PROCESS_HEAP_ENTRY_DDESHARE (needs heap.c support)
 *
 * RETURNS
 *	TRUE: Success
 *	FALSE: Failure
 */
BOOL WINAPI HeapWalk(
              HANDLE heap,               /* [in]  Handle to heap to enumerate */
              LPPROCESS_HEAP_ENTRY entry /* [out] Pointer to structure of enumeration info */
) {
#if 0
    NTSTATUS ret = RtlWalkHeap( heap, entry );
#else
    NTSTATUS ret = HEAP_WalkHeap( heap, entry );
#endif
    if (ret) SetLastError( RtlNtStatusToDosError(ret) );
    return !ret;
}


/***********************************************************************
 *           HeapLock   (KERNEL32.@)
 * Attempts to acquire the critical section object for a specified heap.
 *
 * RETURNS
 *	TRUE: Success
 *	FALSE: Failure
 */
BOOL WINAPI HeapLock(
              HANDLE heap /* [in] Handle of heap to lock for exclusive access */
) {
#if 0
    return RtlLockHeap( heap );
#else
    HEAP *heapPtr = HEAP_GetPtr( heap );
    if (!heapPtr) return FALSE;
    EnterCriticalSection( &heapPtr->critSection );
    return TRUE;
#endif
}


/***********************************************************************
 *           HeapUnlock   (KERNEL32.@)
 * Releases ownership of the critical section object.
 *
 * RETURNS
 *	TRUE: Success
 *	FALSE: Failure
 */
BOOL WINAPI HeapUnlock(
              HANDLE heap /* [in] Handle to the heap to unlock */
) {
#if 0
    return RtlUnlockHeap( heap );
#else
    HEAP *heapPtr = HEAP_GetPtr( heap );
    if (!heapPtr) return FALSE;
    LeaveCriticalSection( &heapPtr->critSection );
    return TRUE;
#endif
}


/***********************************************************************
 *           GetProcessHeaps    (KERNEL32.@)
 */
DWORD WINAPI GetProcessHeaps( DWORD count, HANDLE *heaps )
{
#if 0
    return RtlGetProcessHeaps( count, heaps );
#else
    ULONG total = 1;  /* main heap */
    struct list *ptr;

    EnterCriticalSection( &processHeap->critSection );
    LIST_FOR_EACH( ptr, &processHeap->entry ) total++;
    if (total <= count)
    {
        *heaps++ = processHeap;
        LIST_FOR_EACH( ptr, &processHeap->entry )
            *heaps++ = LIST_ENTRY( ptr, HEAP, entry );
    }
    LeaveCriticalSection( &processHeap->critSection );
    return total;
#endif
}


/* These are needed so that we can call the functions from inside kernel itself */

/***********************************************************************
 *           HeapAlloc    (KERNEL32.@)
 */
LPVOID WINAPI HeapAlloc( HANDLE heap, DWORD flags, SIZE_T size )
{
#if 0
    return RtlAllocateHeap( heap, flags, size );
#else
    ARENA_FREE *pArena;
    ARENA_INUSE *pInUse;
    SUBHEAP *subheap;
    HEAP *heapPtr = HEAP_GetPtr( heap );
    SIZE_T rounded_size;

    /* Validate the parameters */

    if (!heapPtr) return NULL;
    flags &= HEAP_GENERATE_EXCEPTIONS | HEAP_NO_SERIALIZE | HEAP_ZERO_MEMORY;
    flags |= heapPtr->flags;
    rounded_size = ROUND_SIZE(size) + HEAP_TAIL_EXTRA_SIZE( flags );
    if (rounded_size < size)  /* overflow */
    {
#if 0
        if (flags & HEAP_GENERATE_EXCEPTIONS) RtlRaiseStatus( STATUS_NO_MEMORY );
#endif
        return NULL;
    }
    if (rounded_size < HEAP_MIN_DATA_SIZE) rounded_size = HEAP_MIN_DATA_SIZE;

    if (!(flags & HEAP_NO_SERIALIZE)) EnterCriticalSection( &heapPtr->critSection );

    if (rounded_size >= HEAP_MIN_LARGE_BLOCK_SIZE && (flags & HEAP_GROWABLE))
    {
        void *ret = allocate_large_block( heap, flags, size );
        if (!(flags & HEAP_NO_SERIALIZE)) LeaveCriticalSection( &heapPtr->critSection );
#if 0
        if (!ret && (flags & HEAP_GENERATE_EXCEPTIONS)) RtlRaiseStatus( STATUS_NO_MEMORY );
#endif
        TRACE("(%p,%08x,%08lx): returning %p\n", heap, flags, size, ret );
        return ret;
    }

    /* Locate a suitable free block */

    if (!(pArena = HEAP_FindFreeBlock( heapPtr, rounded_size, &subheap )))
    {
        TRACE("(%p,%08x,%08lx): returning NULL\n",
                  heap, flags, size  );
        if (!(flags & HEAP_NO_SERIALIZE)) LeaveCriticalSection( &heapPtr->critSection );
#if 0
        if (flags & HEAP_GENERATE_EXCEPTIONS) RtlRaiseStatus( STATUS_NO_MEMORY );
#endif
        return NULL;
    }

    /* Remove the arena from the free list */

    list_remove( &pArena->entry );

    /* Build the in-use arena */

    pInUse = (ARENA_INUSE *)pArena;

    /* in-use arena is smaller than free arena,
     * so we have to add the difference to the size */
    pInUse->size  = (pInUse->size & ~ARENA_FLAG_FREE) + sizeof(ARENA_FREE) - sizeof(ARENA_INUSE);
    pInUse->magic = ARENA_INUSE_MAGIC;

    /* Shrink the block */

    HEAP_ShrinkBlock( subheap, pInUse, rounded_size );
    pInUse->unused_bytes = (pInUse->size & ARENA_SIZE_MASK) - size;

    notify_alloc( pInUse + 1, size, flags & HEAP_ZERO_MEMORY );
    initialize_block( pInUse + 1, size, pInUse->unused_bytes, flags );

    if (!(flags & HEAP_NO_SERIALIZE)) LeaveCriticalSection( &heapPtr->critSection );

    TRACE("(%p,%08x,%08lx): returning %p\n", heap, flags, size, pInUse + 1 );
    return pInUse + 1;
#endif
}

BOOL WINAPI HeapFree( HANDLE heap, DWORD flags, LPVOID ptr )
{
#if 0
    return RtlFreeHeap( heap, flags, ptr );
#else
    ARENA_INUSE *pInUse;
    SUBHEAP *subheap;
    HEAP *heapPtr;

    /* Validate the parameters */

    if (!ptr) return TRUE;  /* freeing a NULL ptr isn't an error in Win2k */

    heapPtr = HEAP_GetPtr( heap );
    if (!heapPtr)
    {
#if 0
        RtlSetLastWin32ErrorAndNtStatusFromNtStatus( STATUS_INVALID_HANDLE );
#else
        SetLastError( RtlNtStatusToDosError( STATUS_INVALID_HANDLE ));
#endif
        return FALSE;
    }

    flags &= HEAP_NO_SERIALIZE;
    flags |= heapPtr->flags;
    if (!(flags & HEAP_NO_SERIALIZE)) EnterCriticalSection( &heapPtr->critSection );

    /* Inform valgrind we are trying to free memory, so it can throw up an error message */
    notify_free( ptr );

    /* Some sanity checks */
    pInUse  = (ARENA_INUSE *)ptr - 1;
    if (!validate_block_pointer( heapPtr, &subheap, pInUse )) goto error;

    if (!subheap)
        free_large_block( heapPtr, flags, ptr );
    else
        HEAP_MakeInUseBlockFree( subheap, pInUse );

    if (!(flags & HEAP_NO_SERIALIZE)) LeaveCriticalSection( &heapPtr->critSection );
    TRACE("(%p,%08x,%p): returning TRUE\n", heap, flags, ptr );
    return TRUE;

    error:
    if (!(flags & HEAP_NO_SERIALIZE)) LeaveCriticalSection( &heapPtr->critSection );
#if 0
    RtlSetLastWin32ErrorAndNtStatusFromNtStatus( STATUS_INVALID_PARAMETER );
#else
    SetLastError( RtlNtStatusToDosError( STATUS_INVALID_PARAMETER ));
#endif
    TRACE("(%p,%08x,%p): returning FALSE\n", heap, flags, ptr );
    return FALSE;
#endif
}

LPVOID WINAPI HeapReAlloc( HANDLE heap, DWORD flags, LPVOID ptr, SIZE_T size )
{
#if 0
    return RtlReAllocateHeap( heap, flags, ptr, size );
#else
    ARENA_INUSE *pArena;
    HEAP *heapPtr;
    SUBHEAP *subheap;
    SIZE_T oldBlockSize, oldActualSize, rounded_size;
    void *ret;

    if (!ptr) return NULL;
    if (!(heapPtr = HEAP_GetPtr( heap )))
    {
    #if 0
        RtlSetLastWin32ErrorAndNtStatusFromNtStatus( STATUS_INVALID_HANDLE );
#else
        SetLastError( RtlNtStatusToDosError( STATUS_INVALID_HANDLE ));
#endif
        return NULL;
    }

    /* Validate the parameters */

    flags &= HEAP_GENERATE_EXCEPTIONS | HEAP_NO_SERIALIZE | HEAP_ZERO_MEMORY |
             HEAP_REALLOC_IN_PLACE_ONLY;
    flags |= heapPtr->flags;
    if (!(flags & HEAP_NO_SERIALIZE)) EnterCriticalSection( &heapPtr->critSection );

    rounded_size = ROUND_SIZE(size) + HEAP_TAIL_EXTRA_SIZE(flags);
    if (rounded_size < size) goto oom;  /* overflow */
    if (rounded_size < HEAP_MIN_DATA_SIZE) rounded_size = HEAP_MIN_DATA_SIZE;

    pArena = (ARENA_INUSE *)ptr - 1;
    if (!validate_block_pointer( heapPtr, &subheap, pArena )) goto error;
    if (!subheap)
    {
        if (!(ret = realloc_large_block( heapPtr, flags, ptr, size ))) goto oom;
        goto done;
    }

    /* Check if we need to grow the block */

    oldBlockSize = (pArena->size & ARENA_SIZE_MASK);
    oldActualSize = (pArena->size & ARENA_SIZE_MASK) - pArena->unused_bytes;
    if (rounded_size > oldBlockSize)
    {
        char *pNext = (char *)(pArena + 1) + oldBlockSize;

        if (rounded_size >= HEAP_MIN_LARGE_BLOCK_SIZE && (flags & HEAP_GROWABLE))
        {
            if (flags & HEAP_REALLOC_IN_PLACE_ONLY) goto oom;
            if (!(ret = allocate_large_block( heapPtr, flags, size ))) goto oom;
            memcpy( ret, pArena + 1, oldActualSize );
            notify_free( pArena + 1 );
            HEAP_MakeInUseBlockFree( subheap, pArena );
            goto done;
        }
        if ((pNext < (char *)subheap->base + subheap->size) &&
            (*(DWORD *)pNext & ARENA_FLAG_FREE) &&
            (oldBlockSize + (*(DWORD *)pNext & ARENA_SIZE_MASK) + sizeof(ARENA_FREE) >= rounded_size))
        {
            /* The next block is free and large enough */
            ARENA_FREE *pFree = (ARENA_FREE *)pNext;
            list_remove( &pFree->entry );
            pArena->size += (pFree->size & ARENA_SIZE_MASK) + sizeof(*pFree);
            if (!HEAP_Commit( subheap, pArena, rounded_size )) goto oom;
            notify_realloc( pArena + 1, oldActualSize, size );
            HEAP_ShrinkBlock( subheap, pArena, rounded_size );
        }
        else  /* Do it the hard way */
        {
            ARENA_FREE *pNew;
            ARENA_INUSE *pInUse;
            SUBHEAP *newsubheap;

            if ((flags & HEAP_REALLOC_IN_PLACE_ONLY) ||
                !(pNew = HEAP_FindFreeBlock( heapPtr, rounded_size, &newsubheap )))
                goto oom;

            /* Build the in-use arena */

            list_remove( &pNew->entry );
            pInUse = (ARENA_INUSE *)pNew;
            pInUse->size = (pInUse->size & ~ARENA_FLAG_FREE)
                           + sizeof(ARENA_FREE) - sizeof(ARENA_INUSE);
            pInUse->magic = ARENA_INUSE_MAGIC;
            HEAP_ShrinkBlock( newsubheap, pInUse, rounded_size );

            mark_block_initialized( pInUse + 1, oldActualSize );
            notify_alloc( pInUse + 1, size, FALSE );
            memcpy( pInUse + 1, pArena + 1, oldActualSize );

            /* Free the previous block */

            notify_free( pArena + 1 );
            HEAP_MakeInUseBlockFree( subheap, pArena );
            subheap = newsubheap;
            pArena  = pInUse;
        }
    }
    else
    {
        notify_realloc( pArena + 1, oldActualSize, size );
        HEAP_ShrinkBlock( subheap, pArena, rounded_size );
    }

    pArena->unused_bytes = (pArena->size & ARENA_SIZE_MASK) - size;

    /* Clear the extra bytes if needed */

    if (size > oldActualSize)
        initialize_block( (char *)(pArena + 1) + oldActualSize, size - oldActualSize,
                          pArena->unused_bytes, flags );
    else
        mark_block_tail( (char *)(pArena + 1) + size, pArena->unused_bytes, flags );

    /* Return the new arena */

    ret = pArena + 1;
done:
    if (!(flags & HEAP_NO_SERIALIZE)) LeaveCriticalSection( &heapPtr->critSection );
    TRACE("(%p,%08x,%p,%08lx): returning %p\n", heap, flags, ptr, size, ret );
    return ret;

oom:
    if (!(flags & HEAP_NO_SERIALIZE)) LeaveCriticalSection( &heapPtr->critSection );
#if 0
    if (flags & HEAP_GENERATE_EXCEPTIONS) RtlRaiseStatus( STATUS_NO_MEMORY );
    RtlSetLastWin32ErrorAndNtStatusFromNtStatus( STATUS_NO_MEMORY );
#else
    SetLastError( RtlNtStatusToDosError( STATUS_NO_MEMORY ));
#endif
    TRACE("(%p,%08x,%p,%08lx): returning NULL\n", heap, flags, ptr, size );
    return NULL;

error:
    if (!(flags & HEAP_NO_SERIALIZE)) LeaveCriticalSection( &heapPtr->critSection );
#if 0
    RtlSetLastWin32ErrorAndNtStatusFromNtStatus( STATUS_INVALID_PARAMETER );
#else
    SetLastError( RtlNtStatusToDosError( STATUS_INVALID_PARAMETER ));
#endif
    TRACE("(%p,%08x,%p,%08lx): returning NULL\n", heap, flags, ptr, size );
    return NULL;
#endif
}

SIZE_T WINAPI HeapSize( HANDLE heap, DWORD flags, LPCVOID ptr )
{
#if 0
    return RtlSizeHeap( heap, flags, ptr );
#else
    SIZE_T ret;
    const ARENA_INUSE *pArena;
    SUBHEAP *subheap;
    HEAP *heapPtr = HEAP_GetPtr( heap );

    if (!heapPtr)
    {
#if 0
        RtlSetLastWin32ErrorAndNtStatusFromNtStatus( STATUS_INVALID_HANDLE );
#else
        SetLastError( RtlNtStatusToDosError( STATUS_INVALID_HANDLE ));
#endif
        return ~0UL;
    }
    flags &= HEAP_NO_SERIALIZE;
    flags |= heapPtr->flags;
    if (!(flags & HEAP_NO_SERIALIZE)) EnterCriticalSection( &heapPtr->critSection );

    pArena = (const ARENA_INUSE *)ptr - 1;
    if (!validate_block_pointer( heapPtr, &subheap, pArena ))
    {
#if 0
        RtlSetLastWin32ErrorAndNtStatusFromNtStatus( STATUS_INVALID_PARAMETER );
#else
        SetLastError( RtlNtStatusToDosError( STATUS_INVALID_PARAMETER ));
#endif
        ret = ~0UL;
    }
    else if (!subheap)
    {
        const ARENA_LARGE *large_arena = (const ARENA_LARGE *)ptr - 1;
        ret = large_arena->data_size;
    }
    else
    {
        ret = (pArena->size & ARENA_SIZE_MASK) - pArena->unused_bytes;
    }
    if (!(flags & HEAP_NO_SERIALIZE)) LeaveCriticalSection( &heapPtr->critSection );

    TRACE("(%p,%08x,%p): returning %08lx\n", heap, flags, ptr, ret );
    return ret;
#endif
}

/***********************************************************************
 *           RtlQueryHeapInformation    (NTDLL.@)
 */
static NTSTATUS WINAPI HEAP_QueryHeapInformation( HANDLE heap, HEAP_INFORMATION_CLASS info_class,
                                         PVOID info, SIZE_T size_in, PSIZE_T size_out)
{
    switch (info_class)
    {
    case HeapCompatibilityInformation:
        if (size_out) *size_out = sizeof(ULONG);

        if (size_in < sizeof(ULONG))
            return STATUS_BUFFER_TOO_SMALL;

        *(ULONG *)info = 0; /* standard heap */
        return STATUS_SUCCESS;

    default:
        FIXME("Unknown heap information class %u\n", info_class);
        return STATUS_INVALID_INFO_CLASS;
    }
}

BOOL WINAPI HeapQueryInformation( HANDLE heap, HEAP_INFORMATION_CLASS info_class,
                                  PVOID info, SIZE_T size_in, PSIZE_T size_out)
{
#if 0
    NTSTATUS ret = RtlQueryHeapInformation( heap, info_class, info, size_in, size_out );
#else
    NTSTATUS ret = HEAP_QueryHeapInformation( heap, info_class, info, size_in, size_out );
#endif
    if (ret) SetLastError( RtlNtStatusToDosError(ret) );
    return !ret;
}

BOOL WINAPI HeapSetInformation( HANDLE heap, HEAP_INFORMATION_CLASS infoclass, PVOID info, SIZE_T size)
{
#if 0
    NTSTATUS ret = RtlSetHeapInformation( heap, infoclass, info, size );
#else
    NTSTATUS ret = STATUS_SUCCESS;
    FIXME("%p %d %p %ld stub\n", heap, infoclass, info, size);
#endif
    if (ret) SetLastError( RtlNtStatusToDosError(ret) );
    return !ret;
}

/*
 * Win32 Global heap functions (GlobalXXX).
 * These functions included in Win32 for compatibility with 16 bit Windows
 * Especially the moveable blocks and handles are oldish.
 * But the ability to directly allocate memory with GPTR and LPTR is widely
 * used.
 *
 * The handle stuff looks horrible, but it's implemented almost like Win95
 * does it.
 *
 */

#define MAGIC_GLOBAL_USED 0x5342
#define HANDLE_TO_INTERN(h)  ((PGLOBAL32_INTERN)(((char *)(h))-2))
#define INTERN_TO_HANDLE(i)  (&((i)->Pointer))
#define POINTER_TO_HANDLE(p) (*(((const HGLOBAL *)(p))-2))
#define ISHANDLE(h)          (((ULONG_PTR)(h)&2)!=0)
#define ISPOINTER(h)         (((ULONG_PTR)(h)&2)==0)
/* align the storage needed for the HGLOBAL on an 8byte boundary thus
 * GlobalAlloc/GlobalReAlloc'ing with GMEM_MOVEABLE of memory with
 * size = 8*k, where k=1,2,3,... alloc's exactly the given size.
 * The Minolta DiMAGE Image Viewer heavily relies on this, corrupting
 * the output jpeg's > 1 MB if not */
#define HGLOBAL_STORAGE      (sizeof(HGLOBAL)*2)

#include "pshpack1.h"

typedef struct __GLOBAL32_INTERN
{
   WORD         Magic;
   LPVOID       Pointer;
   BYTE         Flags;
   BYTE         LockCount;
} GLOBAL32_INTERN, *PGLOBAL32_INTERN;

#include "poppack.h"

/***********************************************************************
 *           GlobalAlloc   (KERNEL32.@)
 *
 * Allocate a global memory object.
 *
 * RETURNS
 *      Handle: Success
 *      NULL: Failure
 */
HGLOBAL WINAPI GlobalAlloc(
                 UINT flags, /* [in] Object allocation attributes */
                 SIZE_T size /* [in] Number of bytes to allocate */
) {
   PGLOBAL32_INTERN     pintern;
   DWORD                hpflags;
   LPVOID               palloc;

   if(flags&GMEM_ZEROINIT)
      hpflags=HEAP_ZERO_MEMORY;
   else
      hpflags=0;

   if((flags & GMEM_MOVEABLE)==0) /* POINTER */
   {
      palloc = HeapAlloc( GetProcessHeap(), hpflags, max( 1, size ));
      TRACE( "(flags=%04x) returning %p\n",  flags, palloc );
      return palloc;
   }
   else  /* HANDLE */
   {
      if (size > INT_MAX-HGLOBAL_STORAGE)
      {
          SetLastError(ERROR_OUTOFMEMORY);
          return 0;
      }

      pintern = HeapAlloc(GetProcessHeap(), 0, sizeof(GLOBAL32_INTERN));
      if (pintern)
      {
          /* Mask out obsolete flags */
          flags &= ~(GMEM_LOWER | GMEM_NOCOMPACT | GMEM_NOT_BANKED | GMEM_NOTIFY);

          pintern->Magic = MAGIC_GLOBAL_USED;
          pintern->Flags = flags >> 8;
          pintern->LockCount = 0;

          if (size)
          {
              palloc = HeapAlloc(GetProcessHeap(), hpflags, size+HGLOBAL_STORAGE);
              if (!palloc)
              {
                  HeapFree(GetProcessHeap(), 0, pintern);
                  pintern = NULL;
              }
              else
              {
                  *(HGLOBAL *)palloc = INTERN_TO_HANDLE(pintern);
                  pintern->Pointer = (char *)palloc + HGLOBAL_STORAGE;
              }
          }
          else
              pintern->Pointer = NULL;
      }

      if (!pintern) return 0;
      TRACE( "(flags=%04x) returning handle %p pointer %p\n",
             flags, INTERN_TO_HANDLE(pintern), pintern->Pointer );
      return INTERN_TO_HANDLE(pintern);
   }
}


/***********************************************************************
 *           GlobalLock   (KERNEL32.@)
 *
 * Lock a global memory object and return a pointer to first byte of the memory
 *
 * PARAMS
 *  hmem [I] Handle of the global memory object
 *
 * RETURNS
 *  Success: Pointer to first byte of the memory block
 *  Failure: NULL
 *
 * NOTES
 *   When the handle is invalid, last error is set to ERROR_INVALID_HANDLE
 *
 */
LPVOID WINAPI GlobalLock(HGLOBAL hmem)
{
    PGLOBAL32_INTERN pintern;
    LPVOID           palloc;

    if (ISPOINTER(hmem))
        return IsBadReadPtr(hmem, 1) ? NULL : hmem;

#if 0
    RtlLockHeap(GetProcessHeap());
    __TRY
    {
        pintern = HANDLE_TO_INTERN(hmem);
        if (pintern->Magic == MAGIC_GLOBAL_USED)
        {
            palloc = pintern->Pointer;
            if (!pintern->Pointer)
                SetLastError(ERROR_DISCARDED);
            else if (pintern->LockCount < GMEM_LOCKCOUNT)
                pintern->LockCount++;
        }
        else
        {
            WARN("invalid handle %p (Magic: 0x%04x)\n", hmem, pintern->Magic);
            palloc = NULL;
            SetLastError(ERROR_INVALID_HANDLE);
        }
    }
    __EXCEPT_PAGE_FAULT
    {
        WARN("(%p): Page fault occurred ! Caused by bug ?\n", hmem);
        palloc = NULL;
        SetLastError(ERROR_INVALID_HANDLE);
    }
    __ENDTRY
    RtlUnlockHeap(GetProcessHeap());
    return palloc;
#else
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return NULL;
#endif
}


/***********************************************************************
 *           GlobalUnlock   (KERNEL32.@)
 *
 * Unlock a global memory object.
 *
 * PARAMS
 *  hmem [I] Handle of the global memory object
 *
 * RETURNS
 *  Success: Object is still locked
 *  Failure: FALSE (The Object is unlocked)
 *
 * NOTES
 *   When the handle is invalid, last error is set to ERROR_INVALID_HANDLE
 *
 */
BOOL WINAPI GlobalUnlock(HGLOBAL hmem)
{
    PGLOBAL32_INTERN pintern;
    BOOL locked;

    if (ISPOINTER(hmem)) return TRUE;

#if 0
    RtlLockHeap(GetProcessHeap());
    __TRY
    {
        pintern=HANDLE_TO_INTERN(hmem);
        if(pintern->Magic==MAGIC_GLOBAL_USED)
        {
            if(pintern->LockCount)
            {
                pintern->LockCount--;
                locked = (pintern->LockCount != 0);
                if (!locked) SetLastError(NO_ERROR);
            }
            else
            {
                WARN("%p not locked\n", hmem);
                SetLastError(ERROR_NOT_LOCKED);
                locked = FALSE;
            }
        }
        else
        {
            WARN("invalid handle %p (Magic: 0x%04x)\n", hmem, pintern->Magic);
            SetLastError(ERROR_INVALID_HANDLE);
            locked=FALSE;
        }
    }
    __EXCEPT_PAGE_FAULT
    {
        WARN("(%p): Page fault occurred ! Caused by bug ?\n", hmem);
        SetLastError( ERROR_INVALID_PARAMETER );
        locked=FALSE;
    }
    __ENDTRY
    RtlUnlockHeap(GetProcessHeap());
    return locked;
#else
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
#endif
}


/***********************************************************************
 *           GlobalHandle   (KERNEL32.@)
 *
 * Get the handle associated with the pointer to a global memory block.
 *
 * RETURNS
 *      Handle: Success
 *      NULL: Failure
 */
HGLOBAL WINAPI GlobalHandle(
                 LPCVOID pmem /* [in] Pointer to global memory block */
) {
    HGLOBAL handle;
    PGLOBAL32_INTERN  maybe_intern;
    LPCVOID test;

    if (!pmem)
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return 0;
    }

#if 0
    RtlLockHeap(GetProcessHeap());
    __TRY
    {
        handle = 0;

        /* note that if pmem is a pointer to a block allocated by        */
        /* GlobalAlloc with GMEM_MOVEABLE then magic test in HeapValidate  */
        /* will fail.                                                      */
        if (ISPOINTER(pmem)) {
            if (HeapValidate( GetProcessHeap(), HEAP_NO_SERIALIZE, pmem )) {
                handle = (HGLOBAL)pmem;  /* valid fixed block */
                break;
            }
            handle = POINTER_TO_HANDLE(pmem);
        } else
            handle = (HGLOBAL)pmem;

        /* Now test handle either passed in or retrieved from pointer */
        maybe_intern = HANDLE_TO_INTERN( handle );
        if (maybe_intern->Magic == MAGIC_GLOBAL_USED) {
            test = maybe_intern->Pointer;
            if (HeapValidate( GetProcessHeap(), HEAP_NO_SERIALIZE, (const char *)test - HGLOBAL_STORAGE ) && /* obj(-handle) valid arena? */
                HeapValidate( GetProcessHeap(), HEAP_NO_SERIALIZE, maybe_intern ))  /* intern valid arena? */
                break;  /* valid moveable block */
        }
        handle = 0;
        SetLastError( ERROR_INVALID_HANDLE );
    }
    __EXCEPT_PAGE_FAULT
    {
        SetLastError( ERROR_INVALID_HANDLE );
        handle = 0;
    }
    __ENDTRY
    RtlUnlockHeap(GetProcessHeap());

    return handle;
#else
    SetLastError( ERROR_CALL_NOT_IMPLEMENTED );
    return 0;
#endif
}


/***********************************************************************
 *           GlobalReAlloc   (KERNEL32.@)
 *
 * Change the size or attributes of a global memory object.
 *
 * RETURNS
 *      Handle: Success
 *      NULL: Failure
 */
HGLOBAL WINAPI GlobalReAlloc(
                 HGLOBAL hmem, /* [in] Handle of global memory object */
                 SIZE_T size,  /* [in] New size of block */
                 UINT flags    /* [in] How to reallocate object */
) {
#if 0
   LPVOID               palloc;
   HGLOBAL            hnew;
   PGLOBAL32_INTERN     pintern;
   DWORD heap_flags = (flags & GMEM_ZEROINIT) ? HEAP_ZERO_MEMORY : 0;

   hnew = 0;
   RtlLockHeap(GetProcessHeap());
   if(flags & GMEM_MODIFY) /* modify flags */
   {
      if( ISPOINTER(hmem) && (flags & GMEM_MOVEABLE))
      {
         /* make a fixed block moveable
          * actually only NT is able to do this. But it's soo simple
          */
         if (hmem == 0)
         {
             WARN("GlobalReAlloc with null handle!\n");
             SetLastError( ERROR_NOACCESS );
             hnew = 0;
         }
         else
         {
             size = HeapSize(GetProcessHeap(), 0, hmem);
             hnew = GlobalAlloc(flags, size);
             palloc = GlobalLock(hnew);
             memcpy(palloc, hmem, size);
             GlobalUnlock(hnew);
             GlobalFree(hmem);
         }
      }
      else if( ISPOINTER(hmem) &&(flags & GMEM_DISCARDABLE))
      {
         /* change the flags to make our block "discardable" */
         pintern=HANDLE_TO_INTERN(hmem);
         pintern->Flags = pintern->Flags | (GMEM_DISCARDABLE >> 8);
         hnew=hmem;
      }
      else
      {
         SetLastError(ERROR_INVALID_PARAMETER);
         hnew = 0;
      }
   }
   else
   {
      if(ISPOINTER(hmem))
      {
         /* reallocate fixed memory */
         if (!(flags & GMEM_MOVEABLE))
            heap_flags |= HEAP_REALLOC_IN_PLACE_ONLY;
         hnew=HeapReAlloc(GetProcessHeap(), heap_flags, hmem, size);
      }
      else
      {
         /* reallocate a moveable block */
         pintern=HANDLE_TO_INTERN(hmem);

#if 0
/* Apparently Windows doesn't care whether the handle is locked at this point */
/* See also the same comment in GlobalFree() */
         if(pintern->LockCount>1) {
            ERR("handle 0x%08lx is still locked, cannot realloc!\n",(DWORD)hmem);
            SetLastError(ERROR_INVALID_HANDLE);
         } else
#endif
         if(size!=0)
         {
            hnew=hmem;
            if(pintern->Pointer)
            {
               if(size > INT_MAX-HGLOBAL_STORAGE)
               {
                   SetLastError(ERROR_OUTOFMEMORY);
                   hnew = 0;
               }
               else if((palloc = HeapReAlloc(GetProcessHeap(), heap_flags,
                                   (char *) pintern->Pointer-HGLOBAL_STORAGE,
                                   size+HGLOBAL_STORAGE)) == NULL)
                   hnew = 0; /* Block still valid */
               else
                   pintern->Pointer = (char *)palloc+HGLOBAL_STORAGE;
            }
            else
            {
                if(size > INT_MAX-HGLOBAL_STORAGE)
                {
                    SetLastError(ERROR_OUTOFMEMORY);
                    hnew = 0;
                }
                else if((palloc=HeapAlloc(GetProcessHeap(), heap_flags, size+HGLOBAL_STORAGE))
                   == NULL)
                    hnew = 0;
                else
                {
                    *(HGLOBAL *)palloc = hmem;
                    pintern->Pointer = (char *)palloc + HGLOBAL_STORAGE;
                }
            }
         }
         else
         {
            if (pintern->LockCount == 0)
            {
                if(pintern->Pointer)
                {
                    HeapFree(GetProcessHeap(), 0, (char *) pintern->Pointer-HGLOBAL_STORAGE);
                    pintern->Pointer = NULL;
                }
                hnew = hmem;
            }
            else
                WARN("not freeing memory associated with locked handle\n");
         }
      }
   }
   RtlUnlockHeap(GetProcessHeap());
   return hnew;
#else
   SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
   return NULL;
#endif
}


/***********************************************************************
 *           GlobalFree   (KERNEL32.@)
 *
 * Free a global memory object.
 *
 * PARAMS
 *  hmem [I] Handle of the global memory object
 *
 * RETURNS
 *  Success: NULL
 *  Failure: The provided handle
 *
 * NOTES
 *   When the handle is invalid, last error is set to ERROR_INVALID_HANDLE
 *
 */
HGLOBAL WINAPI GlobalFree(HGLOBAL hmem)
{
#if 0
    PGLOBAL32_INTERN pintern;
    HGLOBAL hreturned;

    RtlLockHeap(GetProcessHeap());
    __TRY
    {
        hreturned = 0;
        if(ISPOINTER(hmem)) /* POINTER */
        {
            if(!HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, hmem))
            {
                SetLastError(ERROR_INVALID_HANDLE);
                hreturned = hmem;
            }
        }
        else  /* HANDLE */
        {
            pintern=HANDLE_TO_INTERN(hmem);

            if(pintern->Magic==MAGIC_GLOBAL_USED)
            {
                pintern->Magic = 0xdead;

                /* WIN98 does not make this test. That is you can free a */
                /* block you have not unlocked. Go figure!!              */
                /* if(pintern->LockCount!=0)  */
                /*    SetLastError(ERROR_INVALID_HANDLE);  */

                if(pintern->Pointer)
                    if(!HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, (char *)(pintern->Pointer)-HGLOBAL_STORAGE))
                        hreturned=hmem;
                if(!HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pintern))
                    hreturned=hmem;
            }
            else
            {
                WARN("invalid handle %p (Magic: 0x%04x)\n", hmem, pintern->Magic);
                SetLastError(ERROR_INVALID_HANDLE);
                hreturned = hmem;
            }
        }
    }
    __EXCEPT_PAGE_FAULT
    {
        ERR("invalid handle %p\n", hmem);
        SetLastError(ERROR_INVALID_HANDLE);
        hreturned = hmem;
    }
    __ENDTRY
    RtlUnlockHeap(GetProcessHeap());
    return hreturned;
#else
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return hmem;
#endif
}


/***********************************************************************
 *           GlobalSize   (KERNEL32.@)
 *
 * Get the size of a global memory object.
 *
 * PARAMS
 *  hmem [I] Handle of the global memory object
 *
 * RETURNS
 *  Failure: 0
 *  Success: Size in Bytes of the global memory object
 *
 * NOTES
 *   When the handle is invalid, last error is set to ERROR_INVALID_HANDLE
 *
 */
SIZE_T WINAPI GlobalSize(HGLOBAL hmem)
{
#if 0
   SIZE_T               retval;
   PGLOBAL32_INTERN     pintern;

   if (!((ULONG_PTR)hmem >> 16))
   {
       SetLastError(ERROR_INVALID_HANDLE);
       return 0;
   }

   if(ISPOINTER(hmem))
   {
      retval=HeapSize(GetProcessHeap(), 0, hmem);

      if (retval == ~0ul) /* It might be a GMEM_MOVEABLE data pointer */
      {
          retval = HeapSize(GetProcessHeap(), 0, (char*)hmem - HGLOBAL_STORAGE);
          if (retval != ~0ul) retval -= HGLOBAL_STORAGE;
      }
   }
   else
   {
      RtlLockHeap(GetProcessHeap());
      pintern=HANDLE_TO_INTERN(hmem);

      if(pintern->Magic==MAGIC_GLOBAL_USED)
      {
         if (!pintern->Pointer) /* handle case of GlobalAlloc( ??,0) */
             retval = 0;
         else
         {
             retval = HeapSize(GetProcessHeap(), 0, (char *)pintern->Pointer - HGLOBAL_STORAGE );
             if (retval != ~0ul) retval -= HGLOBAL_STORAGE;
         }
      }
      else
      {
         WARN("invalid handle %p (Magic: 0x%04x)\n", hmem, pintern->Magic);
         SetLastError(ERROR_INVALID_HANDLE);
         retval=0;
      }
      RtlUnlockHeap(GetProcessHeap());
   }
   if (retval == ~0ul) retval = 0;
   return retval;
#else
   SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
   return 0;
#endif
}


/***********************************************************************
 *           GlobalWire   (KERNEL32.@)
 */
LPVOID WINAPI GlobalWire(HGLOBAL hmem)
{
   return GlobalLock( hmem );
}


/***********************************************************************
 *           GlobalUnWire   (KERNEL32.@)
 */
BOOL WINAPI GlobalUnWire(HGLOBAL hmem)
{
   return GlobalUnlock( hmem);
}


/***********************************************************************
 *           GlobalFix   (KERNEL32.@)
 */
VOID WINAPI GlobalFix(HGLOBAL hmem)
{
    GlobalLock( hmem );
}


/***********************************************************************
 *           GlobalUnfix   (KERNEL32.@)
 */
VOID WINAPI GlobalUnfix(HGLOBAL hmem)
{
   GlobalUnlock( hmem);
}


/***********************************************************************
 *           GlobalFlags   (KERNEL32.@)
 *
 * Get information about a global memory object.
 *
 * PARAMS
 *  hmem [I] Handle of the global memory object 
 *
 * RETURNS
 *  Failure: GMEM_INVALID_HANDLE, when the provided handle is invalid 
 *  Success: Value specifying allocation flags and lock count
 *
 */
UINT WINAPI GlobalFlags(HGLOBAL hmem)
{
#if 0
   DWORD                retval;
   PGLOBAL32_INTERN     pintern;

   if(ISPOINTER(hmem))
   {
      retval=0;
   }
   else
   {
      RtlLockHeap(GetProcessHeap());
      pintern=HANDLE_TO_INTERN(hmem);
      if(pintern->Magic==MAGIC_GLOBAL_USED)
      {
         retval=pintern->LockCount + (pintern->Flags<<8);
         if(pintern->Pointer==0)
            retval|= GMEM_DISCARDED;
      }
      else
      {
         WARN("invalid handle %p (Magic: 0x%04x)\n", hmem, pintern->Magic);
         SetLastError(ERROR_INVALID_HANDLE);
         retval = GMEM_INVALID_HANDLE;
      }
      RtlUnlockHeap(GetProcessHeap());
   }
   return retval;
#else
  SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
  return GMEM_INVALID_HANDLE;
#endif
}


/***********************************************************************
 *           GlobalCompact   (KERNEL32.@)
 */
SIZE_T WINAPI GlobalCompact( DWORD minfree )
{
    return 0;  /* GlobalCompact does nothing in Win32 */
}


/***********************************************************************
 *           LocalAlloc   (KERNEL32.@)
 *
 * Allocate a local memory object.
 *
 * RETURNS
 *	Handle: Success
 *	NULL: Failure
 *
 * NOTES
 *  Windows memory management does not provide a separate local heap
 *  and global heap.
 */
HLOCAL WINAPI LocalAlloc( UINT flags, SIZE_T size )
{
    /* LocalAlloc allows a 0-size fixed block, but GlobalAlloc doesn't */
    if (!(flags & LMEM_MOVEABLE))
    {
        DWORD heap_flags = (flags & LMEM_ZEROINIT) ? HEAP_ZERO_MEMORY : 0;
        void *ret = HeapAlloc( GetProcessHeap(), heap_flags, size );
        TRACE( "(flags=%04x) returning %p\n",  flags, ret );
        return ret;
    }
    return GlobalAlloc( flags, size );
}


/***********************************************************************
 *           LocalCompact   (KERNEL32.@)
 */
SIZE_T WINAPI LocalCompact( UINT minfree )
{
    return 0;  /* LocalCompact does nothing in Win32 */
}


/***********************************************************************
 *           LocalFlags   (KERNEL32.@)
 *
 * Get information about a local memory object.
 *
 * RETURNS
 *	Value specifying allocation flags and lock count.
 *	LMEM_INVALID_HANDLE: Failure
 *
 * NOTES
 *  Windows memory management does not provide a separate local heap
 *  and global heap.
 */
UINT WINAPI LocalFlags(
              HLOCAL handle /* [in] Handle of memory object */
) {
    return GlobalFlags( handle );
}


/***********************************************************************
 *           LocalFree   (KERNEL32.@)
 *
 * Free a local memory object.
 *
 * RETURNS
 *	NULL: Success
 *	Handle: Failure
 *
 * NOTES
 *  Windows memory management does not provide a separate local heap
 *  and global heap.
 */
HLOCAL WINAPI LocalFree(
                HLOCAL handle /* [in] Handle of memory object */
) {
    return GlobalFree( handle );
}


/***********************************************************************
 *           LocalHandle   (KERNEL32.@)
 *
 * Get the handle associated with the pointer to a local memory block.
 *
 * RETURNS
 *	Handle: Success
 *	NULL: Failure
 *
 * NOTES
 *  Windows memory management does not provide a separate local heap
 *  and global heap.
 */
HLOCAL WINAPI LocalHandle(
                LPCVOID ptr /* [in] Address of local memory block */
) {
    return GlobalHandle( ptr );
}


/***********************************************************************
 *           LocalLock   (KERNEL32.@)
 * Locks a local memory object and returns pointer to the first byte
 * of the memory block.
 *
 * RETURNS
 *	Pointer: Success
 *	NULL: Failure
 *
 * NOTES
 *  Windows memory management does not provide a separate local heap
 *  and global heap.
 */
LPVOID WINAPI LocalLock(
              HLOCAL handle /* [in] Address of local memory object */
) {
    return GlobalLock( handle );
}


/***********************************************************************
 *           LocalReAlloc   (KERNEL32.@)
 *
 * Change the size or attributes of a local memory object.
 *
 * RETURNS
 *	Handle: Success
 *	NULL: Failure
 *
 * NOTES
 *  Windows memory management does not provide a separate local heap
 *  and global heap.
 */
HLOCAL WINAPI LocalReAlloc(
                HLOCAL handle, /* [in] Handle of memory object */
                SIZE_T size,   /* [in] New size of block */
                UINT flags     /* [in] How to reallocate object */
) {
    return GlobalReAlloc( handle, size, flags );
}


/***********************************************************************
 *           LocalShrink   (KERNEL32.@)
 */
SIZE_T WINAPI LocalShrink( HGLOBAL handle, UINT newsize )
{
    return 0;  /* LocalShrink does nothing in Win32 */
}


/***********************************************************************
 *           LocalSize   (KERNEL32.@)
 *
 * Get the size of a local memory object.
 *
 * RETURNS
 *	Size: Success
 *	0: Failure
 *
 * NOTES
 *  Windows memory management does not provide a separate local heap
 *  and global heap.
 */
SIZE_T WINAPI LocalSize(
              HLOCAL handle /* [in] Handle of memory object */
) {
    return GlobalSize( handle );
}


/***********************************************************************
 *           LocalUnlock   (KERNEL32.@)
 *
 * Unlock a local memory object.
 *
 * RETURNS
 *	TRUE: Object is still locked
 *	FALSE: Object is unlocked
 *
 * NOTES
 *  Windows memory management does not provide a separate local heap
 *  and global heap.
 */
BOOL WINAPI LocalUnlock(
              HLOCAL handle /* [in] Handle of memory object */
)
{
    if (ISPOINTER( handle ))
    {
        SetLastError( ERROR_NOT_LOCKED );
        return FALSE;
    }

    return GlobalUnlock( handle );
}


/***********************************************************************
 *           GlobalMemoryStatusEx   (KERNEL32.@)
 * A version of GlobalMemoryStatus that can deal with memory over 4GB
 *
 * RETURNS
 *	TRUE
 */
BOOL WINAPI GlobalMemoryStatusEx( LPMEMORYSTATUSEX lpmemex )
{
    static MEMORYSTATUSEX	cached_memstatus;
    static int cache_lastchecked = 0;
    SYSTEM_INFO si;
#ifdef linux
    FILE *f;
#elif defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__) || defined(__APPLE__)
    DWORDLONG total;
#ifdef __APPLE__
    unsigned int val;
#else
    unsigned long val;
#endif
    int mib[2];
    size_t size_sys;
#ifdef HW_MEMSIZE
    uint64_t val64;
#endif
#ifdef VM_SWAPUSAGE
    struct xsw_usage swap;
#endif
#elif defined(sun)
    unsigned long pagesize,maxpages,freepages,swapspace,swapfree;
    struct anoninfo swapinf;
    int rval;
#endif

    if (lpmemex->dwLength != sizeof(*lpmemex))
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return FALSE;
    }

    if (time(NULL)==cache_lastchecked) {
	*lpmemex = cached_memstatus;
	return TRUE;
    }
    cache_lastchecked = time(NULL);

    lpmemex->dwMemoryLoad     = 0;
    lpmemex->ullTotalPhys     = 16*1024*1024;
    lpmemex->ullAvailPhys     = 16*1024*1024;
    lpmemex->ullTotalPageFile = 16*1024*1024;
    lpmemex->ullAvailPageFile = 16*1024*1024;

#ifdef linux
    f = fopen( "/proc/meminfo", "r" );
    if (f)
    {
        char buffer[256];
        unsigned long value;

        lpmemex->ullTotalPhys = lpmemex->ullAvailPhys = 0;
        lpmemex->ullTotalPageFile = lpmemex->ullAvailPageFile = 0;
        while (fgets( buffer, sizeof(buffer), f ))
        {
            if (sscanf(buffer, "MemTotal: %lu", &value))
                lpmemex->ullTotalPhys = (ULONG64)value*1024;
            else if (sscanf(buffer, "MemFree: %lu", &value))
                lpmemex->ullAvailPhys = (ULONG64)value*1024;
            else if (sscanf(buffer, "SwapTotal: %lu", &value))
                lpmemex->ullTotalPageFile = (ULONG64)value*1024;
            else if (sscanf(buffer, "SwapFree: %lu", &value))
                lpmemex->ullAvailPageFile = (ULONG64)value*1024;
            else if (sscanf(buffer, "Buffers: %lu", &value))
                lpmemex->ullAvailPhys += (ULONG64)value*1024;
            else if (sscanf(buffer, "Cached: %lu", &value))
                lpmemex->ullAvailPhys += (ULONG64)value*1024;
        }
        fclose( f );
    }
#elif defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__) || defined(__APPLE__)
    total = 0;
    lpmemex->ullAvailPhys = 0;

    mib[0] = CTL_HW;
#ifdef HW_MEMSIZE
    mib[1] = HW_MEMSIZE;
    size_sys = sizeof(val64);
    if (!sysctl(mib, 2, &val64, &size_sys, NULL, 0) && size_sys == sizeof(val64) && val64)
        total = val64;
#endif

#ifdef HAVE_MACH_MACH_H
    {
        host_name_port_t host = mach_host_self();
        mach_msg_type_number_t count;

#ifdef HOST_VM_INFO64_COUNT
        vm_size_t page_size;
        vm_statistics64_data_t vm_stat;

        count = HOST_VM_INFO64_COUNT;
        if (host_statistics64(host, HOST_VM_INFO64, (host_info64_t)&vm_stat, &count) == KERN_SUCCESS &&
            host_page_size(host, &page_size) == KERN_SUCCESS)
            lpmemex->ullAvailPhys = (vm_stat.free_count + vm_stat.inactive_count) * (DWORDLONG)page_size;
#endif
        if (!total)
        {
            host_basic_info_data_t info;
            count = HOST_BASIC_INFO_COUNT;
            if (host_info(host, HOST_BASIC_INFO, (host_info_t)&info, &count) == KERN_SUCCESS)
                total = info.max_mem;
        }

        mach_port_deallocate(mach_task_self(), host);
    }
#endif

    if (!total)
    {
        mib[1] = HW_PHYSMEM;
        size_sys = sizeof(val);
        if (!sysctl(mib, 2, &val, &size_sys, NULL, 0) && size_sys == sizeof(val) && val)
            total = val;
    }

    if (total)
        lpmemex->ullTotalPhys = total;

    if (!lpmemex->ullAvailPhys)
    {
        mib[1] = HW_USERMEM;
        size_sys = sizeof(val);
        if (!sysctl(mib, 2, &val, &size_sys, NULL, 0) && size_sys == sizeof(val) && val)
            lpmemex->ullAvailPhys = val;
    }

    if (!lpmemex->ullAvailPhys)
        lpmemex->ullAvailPhys = lpmemex->ullTotalPhys;

    lpmemex->ullTotalPageFile = lpmemex->ullAvailPhys;
    lpmemex->ullAvailPageFile = lpmemex->ullAvailPhys;

#ifdef VM_SWAPUSAGE
    mib[0] = CTL_VM;
    mib[1] = VM_SWAPUSAGE;
    size_sys = sizeof(swap);
    if (!sysctl(mib, 2, &swap, &size_sys, NULL, 0) && size_sys == sizeof(swap))
    {
        lpmemex->ullTotalPageFile = swap.xsu_total;
        lpmemex->ullAvailPageFile = swap.xsu_avail;
    }
#endif
#elif defined ( sun )
    pagesize=sysconf(_SC_PAGESIZE);
    maxpages=sysconf(_SC_PHYS_PAGES);
    freepages=sysconf(_SC_AVPHYS_PAGES);
    rval=swapctl(SC_AINFO, &swapinf);
    if(rval >-1)
    {
        swapspace=swapinf.ani_max*pagesize;
        swapfree=swapinf.ani_free*pagesize;
    }else
    {

        WARN("Swap size cannot be determined , assuming equal to physical memory\n");
        swapspace=maxpages*pagesize;
        swapfree=maxpages*pagesize;
    }
    lpmemex->ullTotalPhys=pagesize*maxpages;
    lpmemex->ullAvailPhys = pagesize*freepages;
    lpmemex->ullTotalPageFile = swapspace;
    lpmemex->ullAvailPageFile = swapfree;
#endif

    if (lpmemex->ullTotalPhys)
    {
        lpmemex->dwMemoryLoad = (lpmemex->ullTotalPhys-lpmemex->ullAvailPhys)
                                  / (lpmemex->ullTotalPhys / 100);
    }

    /* Win98 returns only the swapsize in ullTotalPageFile/ullAvailPageFile,
       WinXP returns the size of physical memory + swapsize;
       mimic the behavior of XP.
       Note: Project2k refuses to start if it sees less than 1Mb of free swap.
    */
    lpmemex->ullTotalPageFile += lpmemex->ullTotalPhys;
    lpmemex->ullAvailPageFile += lpmemex->ullAvailPhys;

    /* Titan Quest refuses to run if TotalPageFile <= ullTotalPhys */
    if(lpmemex->ullTotalPageFile == lpmemex->ullTotalPhys)
    {
        lpmemex->ullTotalPhys -= 1;
        lpmemex->ullAvailPhys -= 1;
    }

    /* FIXME: should do something for other systems */
    GetSystemInfo(&si);
    lpmemex->ullTotalVirtual  = (ULONG_PTR)si.lpMaximumApplicationAddress-(ULONG_PTR)si.lpMinimumApplicationAddress;
    /* FIXME: we should track down all the already allocated VM pages and subtract them, for now arbitrarily remove 64KB so that it matches NT */
    lpmemex->ullAvailVirtual  = lpmemex->ullTotalVirtual-64*1024;

    /* MSDN says about AvailExtendedVirtual: Size of unreserved and uncommitted
       memory in the extended portion of the virtual address space of the calling
       process, in bytes.
       However, I don't know what this means, so set it to zero :(
    */
    lpmemex->ullAvailExtendedVirtual = 0;

    cached_memstatus = *lpmemex;

    TRACE_(globalmem)("<-- LPMEMORYSTATUSEX: dwLength %d, dwMemoryLoad %d, ullTotalPhys %s, ullAvailPhys %s,"
          " ullTotalPageFile %s, ullAvailPageFile %s, ullTotalVirtual %s, ullAvailVirtual %s\n",
          lpmemex->dwLength, lpmemex->dwMemoryLoad, wine_dbgstr_longlong(lpmemex->ullTotalPhys),
          wine_dbgstr_longlong(lpmemex->ullAvailPhys), wine_dbgstr_longlong(lpmemex->ullTotalPageFile),
          wine_dbgstr_longlong(lpmemex->ullAvailPageFile), wine_dbgstr_longlong(lpmemex->ullTotalVirtual),
          wine_dbgstr_longlong(lpmemex->ullAvailVirtual) );

    return TRUE;
}

/***********************************************************************
 *           GlobalMemoryStatus   (KERNEL32.@)
 * Provides information about the status of the memory, so apps can tell
 * roughly how much they are able to allocate
 *
 * RETURNS
 *      None
 */
VOID WINAPI GlobalMemoryStatus( LPMEMORYSTATUS lpBuffer )
{
    MEMORYSTATUSEX memstatus;
    OSVERSIONINFOW osver;
#if 0
    IMAGE_NT_HEADERS *nt = RtlImageNtHeader( GetModuleHandleW(0) );
#endif

    /* Because GlobalMemoryStatus is identical to GlobalMemoryStatusEX save
       for one extra field in the struct, and the lack of a bug, we simply
       call GlobalMemoryStatusEx and copy the values across. */
    memstatus.dwLength = sizeof(memstatus);
    GlobalMemoryStatusEx(&memstatus);

    lpBuffer->dwLength = sizeof(*lpBuffer);
    lpBuffer->dwMemoryLoad = memstatus.dwMemoryLoad;

    /* Windows 2000 and later report -1 when values are greater than 4 Gb.
     * NT reports values modulo 4 Gb.
     */

    osver.dwOSVersionInfoSize = sizeof(osver);
    GetVersionExW(&osver);

    if ( osver.dwMajorVersion >= 5 || osver.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS )
    {
        lpBuffer->dwTotalPhys = min( memstatus.ullTotalPhys, MAXDWORD );
        lpBuffer->dwAvailPhys = min( memstatus.ullAvailPhys, MAXDWORD );
        /* Limit value for apps that do not expect so much memory. Remove last 512 kb to make Sacrifice demo happy. */
        lpBuffer->dwTotalPageFile = min( memstatus.ullTotalPageFile, 0xfff7ffff );
        lpBuffer->dwAvailPageFile = min( memstatus.ullAvailPageFile, MAXDWORD );
        lpBuffer->dwTotalVirtual = min( memstatus.ullTotalVirtual, MAXDWORD );
        lpBuffer->dwAvailVirtual = min( memstatus.ullAvailVirtual, MAXDWORD );

    }
    else /* duplicate NT bug */
    {
        lpBuffer->dwTotalPhys = memstatus.ullTotalPhys;
        lpBuffer->dwAvailPhys = memstatus.ullAvailPhys;
        lpBuffer->dwTotalPageFile = memstatus.ullTotalPageFile;
        lpBuffer->dwAvailPageFile = memstatus.ullAvailPageFile;
        lpBuffer->dwTotalVirtual = memstatus.ullTotalVirtual;
        lpBuffer->dwAvailVirtual = memstatus.ullAvailVirtual;
    }

#if 0
    /* values are limited to 2Gb unless the app has the IMAGE_FILE_LARGE_ADDRESS_AWARE flag */
    /* page file sizes are not limited (Adobe Illustrator 8 depends on this) */
    if (!(nt->FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE))
    {
        if (lpBuffer->dwTotalPhys > MAXLONG) lpBuffer->dwTotalPhys = MAXLONG;
        if (lpBuffer->dwAvailPhys > MAXLONG) lpBuffer->dwAvailPhys = MAXLONG;
        if (lpBuffer->dwTotalVirtual > MAXLONG) lpBuffer->dwTotalVirtual = MAXLONG;
        if (lpBuffer->dwAvailVirtual > MAXLONG) lpBuffer->dwAvailVirtual = MAXLONG;
    }
#endif

    /* work around for broken photoshop 4 installer */
    if ( lpBuffer->dwAvailPhys +  lpBuffer->dwAvailPageFile >= 2U*1024*1024*1024)
         lpBuffer->dwAvailPageFile = 2U*1024*1024*1024 -  lpBuffer->dwAvailPhys - 1;

#if 0
    /* limit page file size for really old binaries */
    if (nt->OptionalHeader.MajorSubsystemVersion < 4 ||
        nt->OptionalHeader.MajorOperatingSystemVersion < 4)
    {
        if (lpBuffer->dwTotalPageFile > MAXLONG) lpBuffer->dwTotalPageFile = MAXLONG;
        if (lpBuffer->dwAvailPageFile > MAXLONG) lpBuffer->dwAvailPageFile = MAXLONG;
    }
#endif

    TRACE_(globalmem)("Length %u, MemoryLoad %u, TotalPhys %lx, AvailPhys %lx,"
          " TotalPageFile %lx, AvailPageFile %lx, TotalVirtual %lx, AvailVirtual %lx\n",
          lpBuffer->dwLength, lpBuffer->dwMemoryLoad, lpBuffer->dwTotalPhys,
          lpBuffer->dwAvailPhys, lpBuffer->dwTotalPageFile, lpBuffer->dwAvailPageFile,
          lpBuffer->dwTotalVirtual, lpBuffer->dwAvailVirtual );
}

/***********************************************************************
 *           GetPhysicallyInstalledSystemMemory   (KERNEL32.@)
 */
BOOL WINAPI GetPhysicallyInstalledSystemMemory(ULONGLONG *total_memory)
{
    MEMORYSTATUSEX memstatus;

    FIXME("stub: %p\n", total_memory);

    if (!total_memory)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    memstatus.dwLength = sizeof(memstatus);
    GlobalMemoryStatusEx(&memstatus);
    *total_memory = memstatus.ullTotalPhys / 1024;
    return TRUE;
}

BOOL WINAPI GetSystemFileCacheSize(PSIZE_T mincache, PSIZE_T maxcache, PDWORD flags)
{
    FIXME("stub: %p %p %p\n", mincache, maxcache, flags);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI SetSystemFileCacheSize(SIZE_T mincache, SIZE_T maxcache, DWORD flags)
{
    FIXME("stub: %ld %ld %d\n", mincache, maxcache, flags);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI AllocateUserPhysicalPages(HANDLE process, ULONG_PTR *pages, ULONG_PTR *userarray)
{
    FIXME("stub: %p %p %p\n",process, pages, userarray);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI FreeUserPhysicalPages(HANDLE process, ULONG_PTR *pages, ULONG_PTR *userarray)
{
    FIXME("stub: %p %p %p\n", process, pages, userarray);
    *pages = 0;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}
