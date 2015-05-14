#include "dbgexts.h"

char		NameBuffer[1024];
char		NameBufferPrevious[1024];

//symbol variables

bool MemSymbolsOk = false;
ULONG64		MemSymbols[][3] = {
	//[api name][symbol address][symbol data]
	(ULONG64) "nt!MmNonPagedPoolStart", 0, 0,
	(ULONG64) "nt!MmNonPagedPoolEnd0", 0, 0,
	(ULONG64) "nt!MmPagedPoolStart", 0, 0,
	(ULONG64) "nt!MmPagedPoolEnd", 0, 0,
	(ULONG64) "nt!MmNonPagedPoolExpansionStart", 0, 0,
	(ULONG64) "nt!MmNonPagedPoolEnd", 0, 0,
	(ULONG64) "nt!MmSystemRangeStart", 0, 0,
	(ULONG64) "nt!MiExtraResourceStart", 0, 0,
	(ULONG64) "nt!MiExtraResourceEnd", 0, 0,
	(ULONG64) "nt!MiSystemViewStart", 0, 0,
	(ULONG64) "nt!MiSessionPoolStart", 0, 0,
	(ULONG64) "nt!MiSessionPoolEnd", 0, 0,
	(ULONG64) "nt!MiSessionViewStart", 0, 0,
	(ULONG64) "nt!MmSessionSpace", 0, 0,
	(ULONG64) "nt!MiSessionImageStart", 0, 0,
	(ULONG64) "nt!MiSessionImageEnd", 0, 0,
	(ULONG64) "nt!MiSessionSpaceEnd", 0, 0,
	(ULONG64) "nt!MmSystemPteBase", 0, 0,
	(ULONG64) "nt!MmSystemPtesStart", 0, 0,
	(ULONG64) "nt!MmSystemCacheStart", 0, 0,
	(ULONG64) "nt!MmSystemCacheEnd", 0, 0,
	(ULONG64) "nt!MmNonPagedSystemStart", 0, 0,
	0, 0, 0
};

//passing ULONG64 as parameter is not going to work for some
	reason
		// the only way is to pass 32 bit numbers.% 016ll x does not work with printf like functions
		char           *Print64(ULONG32 HighPart, ULONG32 LowPart, char *String){
	wsprintf(String, "%08x%08x", HighPart, LowPart);
	return String;
	}

	//avoid 64 bit parameters...
		void		PrintRange(ULONG32 BasePageAddress, char *BasePage, ULONG32 BaseSize, ULONG32 Attribs){
		char		AttribString[12];
		UINT32		i;
		HRESULT		Result;

//string with attribs:PTWYXSL U / K

			memset(AttribString, ' ', sizeof(AttribString));
		if (Attribs & 1) {
			//page is valid, print hardware information
				AttribString[0] = 'P';

			if (Attribs & 2)
				//RW
			{
				AttribString[2] = 'W';
			}
			if (!(Attribs & 0x80000000))
				//NX
			{
				AttribString[4] = 'X';
			}
			if (Attribs & 0x80) {
				AttribString[6] = 'L';
			}
			if (Attribs & 4)
				//User / Kernel
			{
				AttribString[8] = 'U';
			} else {
				AttribString[8] = 'K';
			}
		} else {
			//Page is not valid, print additionally information aboout Prototype, Transition or Software pages
	// taken from http:	//rekall - forensic.blogspot.ie / 2014 / 10 / windows - virtual - address - translation - and.html
				// the windbg command "dt -r _MMPTE" shows all the PTE formats

				if (!(Attribs & 0x400) && (Attribs & 0x800))
				//prototype = 0 transition = 1
			{
				//Transition PTE
					AttribString[1] = 'T';
			} else if (Attribs & 0x400)
				//prototype = 1
			{
				//Prototype PTE
					AttribString[3] = 'Y';
			} else if (!(Attribs & 0x400) && !(Attribs & 0x800))
				//prototype = 0 transition = 0
			{
				//Software PTE(paged out / zero demand)
					AttribString[5] = 'S';
			}
		}
		AttribString[10] = 0;
		ExtPrintf(" %s %08x %s ", BasePage, BaseSize, AttribString);

		//print the symbols associated to this VA range

			i = 0;
		if (MemSymbolsOk) {
			while (MemSymbols[i][0] != 0) {
				if ((ULONG32) (MemSymbols[i][2]) >= BasePageAddress &&
				    (ULONG32) (MemSymbols[i][2]) < BasePageAddress + BaseSize) {
					ExtPrintf(" - %s", MemSymbols[i][0]);
				}
				i++;
			}
		}
		//print the module names associated with this VA range
			UINT32 j;
		NameBufferPrevious[0] = 0;
		for (i = BasePageAddress; i < BasePageAddress + BaseSize; i += 0x1000) {
			//try to locate the nearest symbol
				Result = g_DebugSymbols->GetNearNameByOffset((ULONG64) (LONG) (i), 0, NameBuffer, 1024, NULL, NULL);
			if (Result == S_OK || Result == S_FALSE) {
				NameBuffer[1023] = 0;
				for (j = 0; j < 1024; j++) {
					if (NameBuffer[j] == '!') {
						NameBuffer[j] = 0;
						break;
					}
				}

				if (j < 1024) {
					//only print the name if it
						was not printed before
							if (strcmp(NameBufferPrevious, NameBuffer) != 0) {
							ExtPrintf(" - %s", NameBuffer);
							strcpy_s(NameBufferPrevious, 1024, NameBuffer);
							NameBufferPrevious[1023] = 0;
						}
				}
			}
		}

		ExtPrintf("\n");
	}

#define PARAM64(__number, __numstring)    Print64((unsigned)__number >> 32, __number, __numstring)

	HRESULT CALLBACK exthelp(PDEBUG_CLIENT4 Client, PCSTR args) {
		INIT_API();

		ExtPrintf("\nUse print_symbol to load the symbols required by the extension \n");
		ExtPrintf("Then use print_layout to print the whole memory layout of the kernelspace. \n");

		EXIT_API();
		return S_OK;
	}

	HRESULT CALLBACK print_layout(PDEBUG_CLIENT4 Client, PCSTR args) {
		INIT_API();

		ULONG64		PteAddress, PteEntry, BasePage;
		ULONG32		BaseAttributes, CurrentAttribs, BaseSize, i;
		ULONG64		Tables [10];
		ULONG		Levels;
		HRESULT		Result;
		char		TempString1[20];

		//flags 0 - based
			// RW bit 1, 0 = read only
			// U / S bit 2, 0 = kernelmode, 1 = usermode
			// PS bit 7, 0 = 4 k, 1 = 4 mb
			// NX bit 63, 1 = no execute
			// W X L U

			ExtPrintf("\n");
		ExtPrintf(" P = present W = writable X = executable L = large\n");
		ExtPrintf(" U/K = user/kernel T = transition Y = prototype S = swapped out/zero demand\n");
		ExtPrintf(" VA        Size   Attributes\n");
		ExtPrintf("-------------------------------------\n");
		BasePage = 0xFFFFFFFFFFFFFFFF;
		BaseAttributes = 0xFFFFFFFF;
		BaseSize = 0;

		for (ULONG64 VAddress = 0x80000000; VAddress < 0xFFFFF000; VAddress += 0x1000) {
			Result = g_DataSpaces2->GetVirtualTranslationPhysicalOffsets(VAddress, Tables, 10, &Levels);
			if (Result != S_OK) {
				//if there
					was a previous buffer, print it out
						if (BasePage != 0xFFFFFFFFFFFFFFFF) {
						PrintRange((ULONG32) BasePage, PARAM64(BasePage, TempString1), BaseSize, BaseAttributes);
					}
				//if the
					symbol refers to a non allocated page, print it here
						i = 0;
				while (MemSymbols[i][0] != 0 && MemSymbolsOk) {
					if ((ULONG32) (MemSymbols[i][2]) >= (ULONG32) VAddress &&
					    (ULONG32) (MemSymbols[i][2]) < (ULONG32) VAddress + 0x1000) {
						ExtPrintf(" %s --------       - %s \n", PARAM64(VAddress, TempString1), MemSymbols[i][0]);
					}
					i++;
				}

				BasePage = 0xFFFFFFFFFFFFFFFF;
				BaseAttributes = 0xFFFFFFFF;
				BaseSize = 0;
				continue;
			}
			PteAddress = Tables[Levels - 2];
			Result = g_DataSpaces->ReadPhysical(PteAddress, &PteEntry, 8, NULL);

			if (BasePage == 0xFFFFFFFFFFFFFFFF) {
				//case first page of buffer
					BasePage = VAddress;
				BaseAttributes = (PteEntry & 0x7FFFFFFF);
				if (PteEntry & 0x8000000000000000)
					//NX bit
				{
					BaseAttributes |= 0x80000000;
				}
				BaseSize = 0x1000;
			} else {
				CurrentAttribs = (PteEntry & 0x7FFFFFFF);
				if (PteEntry & 0x8000000000000000) {
					CurrentAttribs |= 0x80000000;
				}
				bool		new_buf = true;
				if ((BaseAttributes & 1) && (CurrentAttribs & 1)) {
					//if P
						bit is set in both
							if ((BaseAttributes & 0x80000087) == (CurrentAttribs & 0x80000087)) {
							//and other interesting bits are equal in both, the buffer is continuing
								new_buf = false;
						}
				} else if (!(BaseAttributes & 1) && !(CurrentAttribs & 1)) {
					//if P
						bit is not set in both
							if ((BaseAttributes & 0x00000C00) == (CurrentAttribs & 0x00000C00)) {
							//and other interesting bits are equal in both, the buffer is continuing
								new_buf = false;
						}
				}
				//if P
					is different in both, break is obviously necessary

						if (new_buf) {
						//if the
					protection is different:
							//print the buffer and continue
								PrintRange((ULONG32) BasePage, PARAM64(BasePage, TempString1), BaseSize, BaseAttributes);

						//break to a new buffer
							BasePage = VAddress;
						BaseAttributes = (PteEntry & 0x7FFFFFFF);
						if (PteEntry & 0x8000000000000000) {
							BaseAttributes |= 0x80000000;
						}
						BaseSize = 0;
					}
				//case following pages
					BaseSize += 0x1000;
			}
		}

		EXIT_API();
		return S_OK;
	}

	HRESULT CALLBACK print_symbol(PDEBUG_CLIENT4 Client, PCSTR args) {
		INIT_API();

		char		TempString1[20];
		char		TempString2[20];
		UINT32		i;
		HRESULT		Result;

		i = 0;
		while (MemSymbols[i][0] != 0) {
			Result = g_DebugSymbols->GetOffsetByName((char *)(MemSymbols[i][0]), &(MemSymbols[i][1]));
			if (Result != S_OK) {
				ExtPrintf("Error retrieving symbol %s \n", (char *)MemSymbols[i][0]);
				return Result;
			}
			Result = g_DataSpaces->ReadVirtual(MemSymbols[i][1], &(MemSymbols[i][2]), 8, NULL);
			if (Result != S_OK) {
				ExtPrintf("Error reading symbol data for %s \n", (char *)MemSymbols[i][0]);
				return Result;
			}
			ExtPrintf("Symbol retrieved %s, offset: %s data: %s \n", (char *)(MemSymbols[i][0]), PARAM64(MemSymbols[i][1], TempString1), PARAM64(MemSymbols[i][2], TempString2));

			i++;
		}

		MemSymbolsOk = true;

		EXIT_API();
		return S_OK;
	}
