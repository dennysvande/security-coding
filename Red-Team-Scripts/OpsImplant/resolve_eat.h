/**
Helper header file containing routines to manually walk through PEB searching for
loaded modules (KERNEL32.DLL, etc) baseaddress and parse export directory 
manually searching for WinAPI functions (VirtualAlloc, etc) addresses.
**/
#pragma once

#include<Windows.h>
#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include "PEstructs.h"

HMODULE WINAPI GetModHdl(LPCWSTR strModuleName) {

	// get the offset of Process Environment Block
#ifdef _M_IX86 
	PEB* ProcEnvBlk = (PEB*)__readfsdword(0x30);
#else
	PEB* ProcEnvBlk = (PEB*)__readgsqword(0x60);
#endif

	// return base address of a calling module
	if (strModuleName == NULL)
		return (HMODULE)(ProcEnvBlk->ImageBaseAddress);

	PEB_LDR_DATA* Ldr = ProcEnvBlk->Ldr;
	LIST_ENTRY* ModuleList = NULL;

	ModuleList = &Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* pStartListEntry = ModuleList->Flink;

	for (LIST_ENTRY* pListEntry = pStartListEntry;  		// start from beginning of InMemoryOrderModuleList
		pListEntry != ModuleList;	    	// walk all list entries
		pListEntry = pListEntry->Flink) {

		// get current Data Table Entry
		LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY));

		// check if module is found and return its base address
		if (strcmp((const char*)pEntry->BaseDllName.Buffer, (const char*)strModuleName) == 0)
			return (HMODULE)pEntry->DllBase;
	}

	return NULL;

}

FARPROC WINAPI GetFuncAddr(HMODULE hMod, LPCSTR strFuncName) {

	// convert module handle as baseaddress byte
	CHAR* PBaseAddress = (CHAR*)hMod;
	VOID* pFuncAddress = NULL;

	/**
	Populate required structures headers (DOS, NT, Optional) to parse PE headers.
	**/
	PIMAGE_DOS_HEADER PDosHeader = (PIMAGE_DOS_HEADER)PBaseAddress;
	PIMAGE_NT_HEADERS PNtHeader = (PIMAGE_NT_HEADERS)(PBaseAddress + PDosHeader->e_lfanew);
	PIMAGE_OPTIONAL_HEADER POptionalHeader = &PNtHeader->OptionalHeader;
	PIMAGE_DATA_DIRECTORY PExportDataDirectory = (PIMAGE_DATA_DIRECTORY)(&POptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	PIMAGE_EXPORT_DIRECTORY PExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(PBaseAddress + PExportDataDirectory->VirtualAddress);

	/**
	Retrieve starting address for Function address, name and ordinals number tables
	from export directory.
	**/
	PDWORD FuncAddressTable = (PDWORD)(PBaseAddress + PExportDirectory->AddressOfFunctions);
	PDWORD NamesAddressTable = (PDWORD)(PBaseAddress + PExportDirectory->AddressOfNames);
	PWORD OrdinalAddressTable = (PWORD)(PBaseAddress + PExportDirectory->AddressOfNameOrdinals);
	DWORD NumOfNames = (DWORD)PExportDirectory->NumberOfNames;

	/**
	Loop through the tables (array) for matching function name.
	**/
	for (DWORD i = 0; i < NumOfNames; i++)
	{
		char* TmpFuncName = (char*)PBaseAddress + (DWORD_PTR)NamesAddressTable[i];
		if (strcmp(strFuncName, TmpFuncName) == 0) {
			pFuncAddress = (FARPROC)(PBaseAddress + (DWORD_PTR)FuncAddressTable[OrdinalAddressTable[i]]);
			break;
		}
	}

	// return the function address
	return (FARPROC)pFuncAddress;
}