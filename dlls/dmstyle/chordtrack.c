/* IDirectMusicChordTrack Implementation
 *
 * Copyright (C) 2003-2004 Rok Mandeljc
 * Copyright (C) 2003-2004 Raphael Junqueira
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "dmstyle_private.h"
#include "dmobject.h"

WINE_DEFAULT_DEBUG_CHANNEL(dmstyle);
WINE_DECLARE_DEBUG_CHANNEL(dmfile);

/*****************************************************************************
 * IDirectMusicChordTrack implementation
 */
typedef struct IDirectMusicChordTrack {
    IDirectMusicTrack8 IDirectMusicTrack8_iface;
    struct dmobject dmobj;  /* IPersistStream only */
    LONG ref;
    DWORD dwScale;
}  IDirectMusicChordTrack;

/* IDirectMusicChordTrack IDirectMusicTrack8 part: */
static inline IDirectMusicChordTrack *impl_from_IDirectMusicTrack8(IDirectMusicTrack8 *iface)
{
    return CONTAINING_RECORD(iface, IDirectMusicChordTrack, IDirectMusicTrack8_iface);
}

static HRESULT WINAPI IDirectMusicTrack8Impl_QueryInterface(IDirectMusicTrack8 *iface, REFIID riid,
        void **ret_iface)
{
    IDirectMusicChordTrack *This = impl_from_IDirectMusicTrack8(iface);

    TRACE("(%p, %s, %p)\n", This, debugstr_dmguid(riid), ret_iface);

    *ret_iface = NULL;

    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IDirectMusicTrack) ||
            IsEqualIID(riid, &IID_IDirectMusicTrack8))
        *ret_iface = iface;
    else if (IsEqualIID(riid, &IID_IPersistStream))
        *ret_iface = &This->dmobj.IPersistStream_iface;
    else {
        WARN("(%p, %s, %p): not found\n", This, debugstr_dmguid(riid), ret_iface);
        return E_NOINTERFACE;
    }

    IUnknown_AddRef((IUnknown*)*ret_iface);
    return S_OK;
}

static ULONG WINAPI IDirectMusicTrack8Impl_AddRef(IDirectMusicTrack8 *iface)
{
    IDirectMusicChordTrack *This = impl_from_IDirectMusicTrack8(iface);
    LONG ref = InterlockedIncrement(&This->ref);

    TRACE("(%p) ref=%d\n", This, ref);

    return ref;
}

static ULONG WINAPI IDirectMusicTrack8Impl_Release(IDirectMusicTrack8 *iface)
{
    IDirectMusicChordTrack *This = impl_from_IDirectMusicTrack8(iface);
    LONG ref = InterlockedDecrement(&This->ref);

    TRACE("(%p) ref=%d\n", This, ref);

    if (!ref) {
        heap_free(This);
        DMSTYLE_UnlockModule();
    }

    return ref;
}

static HRESULT WINAPI IDirectMusicTrack8Impl_Init(IDirectMusicTrack8 *iface,
        IDirectMusicSegment *pSegment)
{
  IDirectMusicChordTrack *This = impl_from_IDirectMusicTrack8(iface);
  FIXME("(%p, %p): stub\n", This, pSegment);
  return S_OK;
}

static HRESULT WINAPI IDirectMusicTrack8Impl_InitPlay(IDirectMusicTrack8 *iface,
        IDirectMusicSegmentState *pSegmentState, IDirectMusicPerformance *pPerformance,
        void **ppStateData, DWORD dwVirtualTrack8ID, DWORD dwFlags)
{
  IDirectMusicChordTrack *This = impl_from_IDirectMusicTrack8(iface);
  FIXME("(%p, %p, %p, %p, %d, %d): stub\n", This, pSegmentState, pPerformance, ppStateData, dwVirtualTrack8ID, dwFlags);
  return S_OK;
}

static HRESULT WINAPI IDirectMusicTrack8Impl_EndPlay(IDirectMusicTrack8 *iface, void *pStateData)
{
  IDirectMusicChordTrack *This = impl_from_IDirectMusicTrack8(iface);
  FIXME("(%p, %p): stub\n", This, pStateData);
  return S_OK;
}

static HRESULT WINAPI IDirectMusicTrack8Impl_Play(IDirectMusicTrack8 *iface, void *pStateData,
        MUSIC_TIME mtStart, MUSIC_TIME mtEnd, MUSIC_TIME mtOffset, DWORD dwFlags,
        IDirectMusicPerformance *pPerf, IDirectMusicSegmentState *pSegSt, DWORD dwVirtualID)
{
  IDirectMusicChordTrack *This = impl_from_IDirectMusicTrack8(iface);
  FIXME("(%p, %p, %d, %d, %d, %d, %p, %p, %d): stub\n", This, pStateData, mtStart, mtEnd, mtOffset, dwFlags, pPerf, pSegSt, dwVirtualID);
  return S_OK;
}

static HRESULT WINAPI IDirectMusicTrack8Impl_GetParam(IDirectMusicTrack8 *iface, REFGUID rguidType,
        MUSIC_TIME mtTime, MUSIC_TIME *pmtNext, void *pParam)
{
  IDirectMusicChordTrack *This = impl_from_IDirectMusicTrack8(iface);
  FIXME("(%p, %s, %d, %p, %p): stub\n", This, debugstr_dmguid(rguidType), mtTime, pmtNext, pParam);
  return S_OK;
}

static HRESULT WINAPI IDirectMusicTrack8Impl_SetParam(IDirectMusicTrack8 *iface, REFGUID rguidType,
        MUSIC_TIME mtTime, void *pParam)
{
  IDirectMusicChordTrack *This = impl_from_IDirectMusicTrack8(iface);
  FIXME("(%p, %s, %d, %p): stub\n", This, debugstr_dmguid(rguidType), mtTime, pParam);
  return S_OK;
}

static HRESULT WINAPI IDirectMusicTrack8Impl_IsParamSupported(IDirectMusicTrack8 *iface,
        REFGUID rguidType)
{
  IDirectMusicChordTrack *This = impl_from_IDirectMusicTrack8(iface);
  
  TRACE("(%p, %s)\n", This, debugstr_dmguid(rguidType));

  if (!rguidType)
    return E_POINTER;

  if (IsEqualGUID (rguidType, &GUID_BandParam)
      || IsEqualGUID (rguidType, &GUID_ChordParam)
      || IsEqualGUID (rguidType, &GUID_RhythmParam)) {
    TRACE("param supported\n");
    return S_OK;
  }
  TRACE("param unsupported\n");
  return DMUS_E_TYPE_UNSUPPORTED;
}

static HRESULT WINAPI IDirectMusicTrack8Impl_AddNotificationType(IDirectMusicTrack8 *iface,
        REFGUID rguidNotificationType)
{
  IDirectMusicChordTrack *This = impl_from_IDirectMusicTrack8(iface);
  FIXME("(%p, %s): stub\n", This, debugstr_dmguid(rguidNotificationType));
  return S_OK;
}

static HRESULT WINAPI IDirectMusicTrack8Impl_RemoveNotificationType(IDirectMusicTrack8 *iface,
        REFGUID rguidNotificationType)
{
  IDirectMusicChordTrack *This = impl_from_IDirectMusicTrack8(iface);
  FIXME("(%p, %s): stub\n", This, debugstr_dmguid(rguidNotificationType));
  return S_OK;
}

static HRESULT WINAPI IDirectMusicTrack8Impl_Clone(IDirectMusicTrack8 *iface, MUSIC_TIME mtStart,
        MUSIC_TIME mtEnd, IDirectMusicTrack **ppTrack)
{
  IDirectMusicChordTrack *This = impl_from_IDirectMusicTrack8(iface);
  FIXME("(%p, %d, %d, %p): stub\n", This, mtStart, mtEnd, ppTrack);
  return S_OK;
}

static HRESULT WINAPI IDirectMusicTrack8Impl_PlayEx(IDirectMusicTrack8 *iface, void *pStateData,
        REFERENCE_TIME rtStart, REFERENCE_TIME rtEnd, REFERENCE_TIME rtOffset, DWORD dwFlags,
        IDirectMusicPerformance *pPerf, IDirectMusicSegmentState *pSegSt, DWORD dwVirtualID)
{
  IDirectMusicChordTrack *This = impl_from_IDirectMusicTrack8(iface);
  FIXME("(%p, %p, 0x%s, 0x%s, 0x%s, %d, %p, %p, %d): stub\n", This, pStateData, wine_dbgstr_longlong(rtStart),
      wine_dbgstr_longlong(rtEnd), wine_dbgstr_longlong(rtOffset), dwFlags, pPerf, pSegSt, dwVirtualID);
  return S_OK;
}

static HRESULT WINAPI IDirectMusicTrack8Impl_GetParamEx(IDirectMusicTrack8 *iface,
        REFGUID rguidType, REFERENCE_TIME rtTime, REFERENCE_TIME *prtNext, void *pParam,
        void *pStateData, DWORD dwFlags)
{
  IDirectMusicChordTrack *This = impl_from_IDirectMusicTrack8(iface);
  FIXME("(%p, %s, 0x%s, %p, %p, %p, %d): stub\n", This, debugstr_dmguid(rguidType),
      wine_dbgstr_longlong(rtTime), prtNext, pParam, pStateData, dwFlags);
  return S_OK;
}

static HRESULT WINAPI IDirectMusicTrack8Impl_SetParamEx(IDirectMusicTrack8 *iface,
        REFGUID rguidType, REFERENCE_TIME rtTime, void *pParam, void *pStateData, DWORD dwFlags)
{
  IDirectMusicChordTrack *This = impl_from_IDirectMusicTrack8(iface);
  FIXME("(%p, %s, 0x%s, %p, %p, %d): stub\n", This, debugstr_dmguid(rguidType),
      wine_dbgstr_longlong(rtTime), pParam, pStateData, dwFlags);
  return S_OK;
}

static HRESULT WINAPI IDirectMusicTrack8Impl_Compose(IDirectMusicTrack8 *iface, IUnknown *context,
        DWORD trackgroup, IDirectMusicTrack **track)
{
    IDirectMusicChordTrack *This = impl_from_IDirectMusicTrack8(iface);

    TRACE("(%p, %p, %d, %p): method not implemented\n", This, context, trackgroup, track);
    return E_NOTIMPL;
}

static HRESULT WINAPI IDirectMusicTrack8Impl_Join(IDirectMusicTrack8 *iface,
        IDirectMusicTrack *pNewTrack, MUSIC_TIME mtJoin, IUnknown *pContext, DWORD dwTrackGroup,
        IDirectMusicTrack **ppResultTrack)
{
  IDirectMusicChordTrack *This = impl_from_IDirectMusicTrack8(iface);
  FIXME("(%p, %p, %d, %p, %d, %p): stub\n", This, pNewTrack, mtJoin, pContext, dwTrackGroup, ppResultTrack);
  return S_OK;
}

static const IDirectMusicTrack8Vtbl dmtrack8_vtbl = {
    IDirectMusicTrack8Impl_QueryInterface,
    IDirectMusicTrack8Impl_AddRef,
    IDirectMusicTrack8Impl_Release,
    IDirectMusicTrack8Impl_Init,
    IDirectMusicTrack8Impl_InitPlay,
    IDirectMusicTrack8Impl_EndPlay,
    IDirectMusicTrack8Impl_Play,
    IDirectMusicTrack8Impl_GetParam,
    IDirectMusicTrack8Impl_SetParam,
    IDirectMusicTrack8Impl_IsParamSupported,
    IDirectMusicTrack8Impl_AddNotificationType,
    IDirectMusicTrack8Impl_RemoveNotificationType,
    IDirectMusicTrack8Impl_Clone,
    IDirectMusicTrack8Impl_PlayEx,
    IDirectMusicTrack8Impl_GetParamEx,
    IDirectMusicTrack8Impl_SetParamEx,
    IDirectMusicTrack8Impl_Compose,
    IDirectMusicTrack8Impl_Join
};

static HRESULT parse_chordtrack_list(IDirectMusicChordTrack *This, DMUS_PRIVATE_CHUNK *pChunk,
        IStream *pStm)
{
  DMUS_PRIVATE_CHUNK Chunk;
  DWORD ListSize[3], ListCount[3];
  LARGE_INTEGER liMove; /* used when skipping chunks */

  if (pChunk->fccID != DMUS_FOURCC_CHORDTRACK_LIST) {
    ERR_(dmfile)(": %s chunk should be a CHORDTRACK list\n", debugstr_fourcc (pChunk->fccID));
    return E_FAIL;
  }  

  ListSize[0] = pChunk->dwSize - sizeof(FOURCC);
  ListCount[0] = 0;

  do {
    IStream_Read (pStm, &Chunk, sizeof(FOURCC)+sizeof(DWORD), NULL);
    ListCount[0] += sizeof(FOURCC) + sizeof(DWORD) + Chunk.dwSize;
    TRACE_(dmfile)(": %s chunk (size = %d)", debugstr_fourcc (Chunk.fccID), Chunk.dwSize);
    switch (Chunk.fccID) { 
    case DMUS_FOURCC_CHORDTRACKHEADER_CHUNK: {
      TRACE_(dmfile)(": Chord track header chunk\n");
      IStream_Read (pStm, &This->dwScale, sizeof(DWORD), NULL);
      TRACE_(dmfile)(" - dwScale: %d\n", This->dwScale);
      break;
    }
    case DMUS_FOURCC_CHORDTRACKBODY_CHUNK: {
      DWORD sz;
      DWORD it;
      DWORD num;
      DMUS_IO_CHORD body;
      DMUS_IO_SUBCHORD subchords;

      TRACE_(dmfile)(": Chord track body chunk\n");

      IStream_Read (pStm, &sz, sizeof(DWORD), NULL);
      TRACE_(dmfile)(" - sizeof(DMUS_IO_CHORD): %d\n", sz);
      if (sz != sizeof(DMUS_IO_CHORD)) return E_FAIL;
      IStream_Read (pStm, &body, sizeof(DMUS_IO_CHORD), NULL);
      TRACE_(dmfile)(" - wszName: %s\n", debugstr_w(body.wszName));
      TRACE_(dmfile)(" - mtTime: %u\n", body.mtTime);
      TRACE_(dmfile)(" - wMeasure: %u\n", body.wMeasure);
      TRACE_(dmfile)(" - bBeat:  %u\n", body.bBeat);
      TRACE_(dmfile)(" - bFlags: 0x%02x\n", body.bFlags);
      
      IStream_Read (pStm, &num, sizeof(DWORD), NULL);
      TRACE_(dmfile)(" - # DMUS_IO_SUBCHORDS: %d\n", num);
      IStream_Read (pStm, &sz, sizeof(DWORD), NULL);
      TRACE_(dmfile)(" - sizeof(DMUS_IO_SUBCHORDS): %d\n", sz);
      if (sz != sizeof(DMUS_IO_SUBCHORD)) return E_FAIL;

      for (it = 0; it < num; ++it) {
	IStream_Read (pStm, &subchords, sizeof(DMUS_IO_SUBCHORD), NULL);
	TRACE_(dmfile)("DMUS_IO_SUBCHORD #%d\n", it+1);
	TRACE_(dmfile)(" - dwChordPattern: %u\n", subchords.dwChordPattern);
	TRACE_(dmfile)(" - dwScalePattern: %u\n", subchords.dwScalePattern);
	TRACE_(dmfile)(" - dwInversionPoints: %u\n", subchords.dwInversionPoints);
	TRACE_(dmfile)(" - dwLevels: %u\n", subchords.dwLevels);
	TRACE_(dmfile)(" - bChordRoot:  %u\n", subchords.bChordRoot);
	TRACE_(dmfile)(" - bScaleRoot: %u\n", subchords.bScaleRoot);
      }
      break;
    }
    default: {
      TRACE_(dmfile)(": unknown chunk (irrelevant & skipping)\n");
      liMove.QuadPart = Chunk.dwSize;
      IStream_Seek (pStm, liMove, STREAM_SEEK_CUR, NULL);
      break;		
    }
    }
    TRACE_(dmfile)(": ListCount[0] = %d < ListSize[0] = %d\n", ListCount[0], ListSize[0]);
  } while (ListCount[0] < ListSize[0]);

  return S_OK;
}

static inline IDirectMusicChordTrack *impl_from_IPersistStream(IPersistStream *iface)
{
    return CONTAINING_RECORD(iface, IDirectMusicChordTrack, dmobj.IPersistStream_iface);
}

static HRESULT WINAPI IPersistStreamImpl_Load(IPersistStream *iface, IStream *pStm)
{
  IDirectMusicChordTrack *This = impl_from_IPersistStream(iface);
  DMUS_PRIVATE_CHUNK Chunk;
  LARGE_INTEGER liMove;
  HRESULT hr;
 
  TRACE("(%p, %p): Loading\n", This, pStm);

  IStream_Read (pStm, &Chunk, sizeof(FOURCC)+sizeof(DWORD), NULL);
  TRACE_(dmfile)(": %s chunk (size = %d)", debugstr_fourcc (Chunk.fccID), Chunk.dwSize);
  switch (Chunk.fccID) {	
  case FOURCC_LIST: {
    IStream_Read (pStm, &Chunk.fccID, sizeof(FOURCC), NULL);
    TRACE_(dmfile)(": %s chunk (size = %d)", debugstr_fourcc (Chunk.fccID), Chunk.dwSize);
    switch (Chunk.fccID) { 
    case DMUS_FOURCC_CHORDTRACK_LIST: {
      TRACE_(dmfile)(": Chord track list\n");
      hr = parse_chordtrack_list(This, &Chunk, pStm);
      if (FAILED(hr)) return hr;
      break;    
    }
    default: {
      TRACE_(dmfile)(": unexpected chunk; loading failed)\n");
      liMove.QuadPart = Chunk.dwSize;
      IStream_Seek (pStm, liMove, STREAM_SEEK_CUR, NULL);
      return E_FAIL;
    }
    }
    TRACE_(dmfile)(": reading finished\n");
    break;
  }
  default: {
    TRACE_(dmfile)(": unexpected chunk; loading failed)\n");
    liMove.QuadPart = Chunk.dwSize;
    IStream_Seek (pStm, liMove, STREAM_SEEK_CUR, NULL); /* skip the rest of the chunk */
    return E_FAIL;
  }
  }

  return S_OK;
}

static HRESULT WINAPI IPersistStreamImpl_Save(IPersistStream *iface, IStream *stream,
        BOOL cleardirty)
{
    IDirectMusicChordTrack *This = impl_from_IPersistStream(iface);

    FIXME("(%p, %p, %d): stub\n", This, stream, cleardirty);

    if (!stream)
        return E_POINTER;

    return E_NOTIMPL;
}

static const IPersistStreamVtbl persiststream_vtbl = {
    dmobj_IPersistStream_QueryInterface,
    dmobj_IPersistStream_AddRef,
    dmobj_IPersistStream_Release,
    dmobj_IPersistStream_GetClassID,
    unimpl_IPersistStream_IsDirty,
    IPersistStreamImpl_Load,
    IPersistStreamImpl_Save,
    unimpl_IPersistStream_GetSizeMax
};

/* for ClassFactory */
HRESULT WINAPI create_dmchordtrack(REFIID lpcGUID, void **ppobj)
{
    IDirectMusicChordTrack *track;
    HRESULT hr;

    track = heap_alloc_zero(sizeof(*track));
    if (!track) {
        *ppobj = NULL;
        return E_OUTOFMEMORY;
    }
    track->IDirectMusicTrack8_iface.lpVtbl = &dmtrack8_vtbl;
    track->ref = 1;
    dmobject_init(&track->dmobj, &CLSID_DirectMusicChordTrack,
                  (IUnknown *)&track->IDirectMusicTrack8_iface);
    track->dmobj.IPersistStream_iface.lpVtbl = &persiststream_vtbl;

    DMSTYLE_LockModule();
    hr = IDirectMusicTrack8_QueryInterface(&track->IDirectMusicTrack8_iface, lpcGUID, ppobj);
    IDirectMusicTrack8_Release(&track->IDirectMusicTrack8_iface);

    return hr;
}
