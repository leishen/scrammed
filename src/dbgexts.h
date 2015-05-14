#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KDEXT_64BIT
#include <wdbgexts.h>
#include <dbgeng.h>

#pragma warning(disable:4201) // nonstandard extension used : nameless struct
#include <extsfns.h>

#ifdef __cplusplus
extern		"C" {
#endif


#define INIT_API()               \
	HRESULT		Status;
	               \
	if              ((Status = ExtQuery(Client)) != S_OK)
				return	Status;

#define EXT_RELEASE(Unk) \
	                ((Unk) != NULL ? ((Unk)->Release(), (Unk) = NULL) : NULL)
#define EXIT_API   ExtRelease

	//		Global	variables initialized by query.
	extern PDEBUG_DATA_SPACES2 g_DataSpaces2;
	extern PDEBUG_DATA_SPACES g_DataSpaces;
	extern PDEBUG_SYMBOLS g_DebugSymbols;

	HRESULT		ExtQuery(PDEBUG_CLIENT4 Client);
	void		ExtRelease(void);
	HRESULT		NotifyOnTargetAccessible(PDEBUG_CONTROL Control);
	void __cdecl	ExtPrintf(PCSTR Format,...);

#ifdef __cplusplus
}
#endif
