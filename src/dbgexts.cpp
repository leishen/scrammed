#include "dbgexts.h"

PDEBUG_CLIENT4	g_ExtClient;
PDEBUG_CONTROL	g_ExtControl;
PDEBUG_DATA_SPACES2 g_DataSpaces2;
PDEBUG_DATA_SPACES g_DataSpaces;
PDEBUG_SYMBOLS	g_DebugSymbols;
PDEBUG_SYMBOLS2	g_ExtSymbols;

extern		"C"	HRESULT 
ExtQuery(PDEBUG_CLIENT4 Client)
{
	HRESULT		Status;

	if ((Status = Client->QueryInterface(__uuidof(IDebugControl), (void **)&g_ExtControl)) != S_OK) {
		goto Fail;
	}
	if ((Status = Client->QueryInterface(__uuidof(IDebugSymbols2), (void **)&g_ExtSymbols)) != S_OK) {
		goto Fail;
	}
	if ((Status = Client->QueryInterface(__uuidof(IDebugDataSpaces2), (void **)&g_DataSpaces2)) != S_OK) {
		goto Fail;
	}
	if ((Status = Client->QueryInterface(__uuidof(IDebugDataSpaces), (void **)&g_DataSpaces)) != S_OK) {
		goto Fail;
	}
	if ((Status = Client->QueryInterface(__uuidof(IDebugSymbols), (void **)&g_DebugSymbols)) != S_OK) {
		goto Fail;
	}
	g_ExtClient = Client;

	return S_OK;

Fail:
	ExtRelease();
	return Status;
}

void 
ExtRelease(void)
{
	g_ExtClient = NULL;
	EXT_RELEASE(g_ExtControl);
	EXT_RELEASE(g_ExtSymbols);
}

void __cdecl 
ExtPrintf(PCSTR Format,...)
{
	va_list		Args;

	va_start(Args, Format);
	g_ExtControl->OutputVaList(DEBUG_OUTCTL_ALL_CLIENTS, Format, Args);
	va_end(Args);
}

extern		"C"	HRESULT CALLBACK 
DebugExtensionInitialize(PULONG Version, PULONG Flags)
{
	*Version = DEBUG_EXTENSION_VERSION(1, 0);
	*Flags = 0;
	return S_OK;
}

extern		"C" void CALLBACK 
DebugExtensionNotify(ULONG Notify, ULONG64 Argument)
{
	return;
}

extern		"C" void CALLBACK 
DebugExtensionUninitialize(void)
{
	return;
}

extern		"C"	HRESULT CALLBACK 
KnownStructOutput(ULONG Flag, ULONG64 Address, PSTR StructName, PSTR Buffer, PULONG BufferSize)
{
	return S_OK;
}
