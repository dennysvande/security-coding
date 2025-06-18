/*
 * A program / capability to do recon on a windows machine to achieve situational awareness during
 * penetration test, adversary emulation or simulation. Rework as BOF for operationalization with C2.
 *
 * usage: SituationalAwareness.exe [whoami|net users|sysinfo]
 *
 * Author: Dennys Simbolon
 * Date  : 14-06-2025
 */

#pragma once
#include <winsock2.h>
#include <iphlpapi.h>
#include "helperstructs.h"

#pragma comment(lib, "iphlpapi.lib")


void DisplayError(DWORD errorCode) {

	DWORD dwFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
	LPCVOID lpSource = NULL;
	DWORD dwMessageId = errorCode;
	DWORD dwLanguageId = NULL;
	LPWSTR msgBuffer = NULL;
	DWORD nSize = NULL;
	DWORD retVal;

	retVal = FormatMessageW(dwFlags, lpSource, dwMessageId, dwLanguageId, (LPWSTR)&msgBuffer, nSize, NULL);

	if (retVal == NULL) {
		printf("Failed to get error message with error: %d\n", GetLastError());
	}
	else {
		printf("Encounter an error: %ls\n", msgBuffer);
	}
}

void GetSysinfo(void) {

	/**
	Retrieve Windows Major (5,6,10), Minor version (0,1), build number and processor architecture
	from a shared data structure KUSER_SHARED_DATA_ADDRESS in memory starting at
	Virtual Address 0x7FFE0000 and display it to stdout.
	**/

	SYSTEM_INFO archInfo;
	PKUSER_SHARED_DATA sysInfo = (PKUSER_SHARED_DATA)KUSER_SHARED_DATA_ADDRESS;
	GetNativeSystemInfo(&archInfo);
	switch (archInfo.wProcessorArchitecture) {
		case PROCESSOR_ARCHITECTURE_AMD64:
			printf("Windows Version: %d.%d %d x64\n", sysInfo->NtMajorVersion, sysInfo->NtMinorVersion, sysInfo->NtBuildNumber);
			break;
		case PROCESSOR_ARCHITECTURE_ARM64:
			printf("Windows Version: %d.%d %d ARM64\n", sysInfo->NtMajorVersion, sysInfo->NtMinorVersion, sysInfo->NtBuildNumber);
			break;
		case PROCESSOR_ARCHITECTURE_IA64:
			printf("Windows Version: %d.%d %d Intel Itanium-based\n", sysInfo->NtMajorVersion, sysInfo->NtMinorVersion, sysInfo->NtBuildNumber);
			break;
		case PROCESSOR_ARCHITECTURE_INTEL:
			printf("Windows Version: %d.%d %d x86\n", sysInfo->NtMajorVersion, sysInfo->NtMinorVersion, sysInfo->NtBuildNumber);
			break;
		case PROCESSOR_ARCHITECTURE_ARM:
			printf("Windows Version: %d.%d %d ARM\n", sysInfo->NtMajorVersion, sysInfo->NtMinorVersion, sysInfo->NtBuildNumber);
			break;
		case PROCESSOR_ARCHITECTURE_UNKNOWN:
			printf("Windows Version: %d.%d %d Unknown architecture\n", sysInfo->NtMajorVersion, sysInfo->NtMinorVersion, sysInfo->NtBuildNumber);
			break;
	}

}

void GetHostname(void) {
	
	/*
	 * Retrieve hostname.
	 */

	wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD dwSize = MAX_COMPUTERNAME_LENGTH + 1;
	
	BOOL hostname = GetComputerNameW(buffer, &dwSize);

	if (hostname != NULL) {
		printf("%ls\n", buffer);
	}
	else {
		DisplayError(GetLastError());
	}
}

void GetWhoami(void) {

	/**
	Retrieve current user name and display the username to stdout.
	**/

	wchar_t userName[256];
	DWORD cbSize = 256;

	DWORD user = GetUserNameW(userName, &cbSize);

	if (user != 0) {
		printf("%ls\n", userName);
	}
	else {
		DisplayError(GetLastError());
	}
}

void GetUsers(void) {

	/**
	Retrieve a list of users exists on the local machine and display the list to stdout.
	**/

	LPUSER_INFO_2 bufPtr = NULL;
	DWORD dwLevel = 2;
	DWORD dwEntriesRead = NULL;
	DWORD dwTotalEntries = NULL;
	NET_API_STATUS nStatus;

	nStatus = NetUserEnum(NULL, dwLevel, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&bufPtr, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, NULL);

	if (nStatus == NERR_Success) {
		for (DWORD i = 0; i < (DWORD)dwTotalEntries; i++) {
			wprintf(L"%s\n", bufPtr->usri2_name);
			bufPtr++;
		}
	}
	else {
		DisplayError(nStatus);
	}

	NetApiBufferFree(bufPtr);

}

void GetUserInfo(wchar_t * user) {

	/*
	 * Retrieve user details info similar to net.exe user command.
	 * Details of user obtained is define in USER_INFO_2 structure.
	 */

	wchar_t * serverName = NULL;
	wchar_t * userName = user;
	DWORD dwLevel = 2;
	LPUSER_INFO_2 userInfoBuf = NULL;
	NET_API_STATUS netStatus;
	
	netStatus = NetUserGetInfo(NULL, userName, dwLevel, (LPBYTE*) &userInfoBuf);

	if (netStatus == NERR_Success) {
		printf("%-27ls %ls\n", L"User name", userInfoBuf->usri2_name);
		printf("%-27ls %ls\n", L"Full name", userInfoBuf->usri2_full_name);
		printf("%-27ls %ls\n", L"Comment", userInfoBuf->usri2_comment);
		printf("%-27ls %ls\n", L"User's Comment", userInfoBuf->usri2_usr_comment);
		return;
	}
	else {
		DisplayError(netStatus);
	}

}

// needs to be fixed
void GetHotfixes(void) {

	HRESULT initCom = CoInitialize(NULL);
	IUpdateSession* updateSession;
	IUpdateSearcher* updateSearch;
	ISearchResult* results;
	IUpdateCollection* updateList;
	IUpdate* updateItem;
	BSTR updateName;
	LONG updateSize;
	LONG index = 0;
	DWORD dwClsContext = CLSCTX_INPROC_SERVER;
	BSTR criteria = SysAllocString(L"(IsInstalled=1) OR (IsHidden=1)");

	HRESULT updateObject = CoCreateInstance(CLSID_UpdateSession, NULL, dwClsContext, IID_IUpdateSession, (PVOID*)&updateSession);
	
	updateSession->CreateUpdateSearcher(&updateSearch);
	updateSearch->Search(criteria, &results);

	results->get_Updates(&updateList);
	updateList->get_Count(&updateSize);

	for (; index < updateSize; index++) {
		updateList->get_Item(index, &updateItem);
		updateItem->get_Title(&updateName);
		printf("%ls", updateName);
	}

}

void GetRemoteProcesses(void) {

	/**
	Retrieve running processes on a local or remote machine using
	Windows Terminal Services (WTS) API.
	**/

	HANDLE hServer = WTS_CURRENT_SERVER_HANDLE;
	DWORD dwLevel = 1;
	DWORD SessionId = WTS_ANY_SESSION;
	LPWSTR processInfo;
	DWORD dwCount;
	DWORD dwIndex = 0;

	BOOL procEnum = WTSEnumerateProcessesExW(hServer, &dwLevel, SessionId, &processInfo, &dwCount);

	if (procEnum == 0) {
		DisplayError(GetLastError());
		return;
	}

	if (processInfo == NULL) {
		printf("No process is found.\n");
		return;
	}

	WTS_PROCESS_INFO_EXW* pProcessInfo = (WTS_PROCESS_INFO_EXW*)processInfo;

	printf("%-7ls %-45ls %-7ls\n", L"PID", L"Process Name", L"Session Id");

	for (; dwIndex < dwCount; dwIndex++) {
		printf("%-7d %-45ls %-7d\n", pProcessInfo->ProcessId, pProcessInfo->pProcessName, pProcessInfo->SessionId);
		pProcessInfo++;
	}

	WTSFreeMemoryExW(WTSTypeProcessInfoLevel1, processInfo, dwCount);
	CloseHandle(hServer);

}

void GetProcesses(void) {

	/**
	Capture a snapshot of running processes on the local machine,
	and display the PID, PPID, Process Name to stdout."
	**/
	
	DWORD dwFlags = TH32CS_SNAPPROCESS;
	DWORD th32ProcessID = NULL;
	PROCESSENTRY32 procEntry32;
	procEntry32.dwSize = sizeof(PROCESSENTRY32);

	HANDLE procSnapshot = CreateToolhelp32Snapshot(dwFlags, th32ProcessID);

	if (procSnapshot == INVALID_HANDLE_VALUE) {
		DisplayError(GetLastError());
		//printf("Process snapshot failed with error: %d\n", GetLastError());
		return;
	}

	printf("%-7s %-7s %-7s\n", "PID", "PPID", "Process Name");
	Process32First(procSnapshot, &procEntry32);

	do {
		printf("%-7d %-7d %-7ws\n", procEntry32.th32ProcessID, procEntry32.th32ParentProcessID, procEntry32.szExeFile);
	} while (Process32Next(procSnapshot, &procEntry32));

	CloseHandle(procSnapshot);

}

void GetDirectoryList(wchar_t * directory) {

	/*
	 * List directory content
	 */
	
	wchar_t directoryPath[MAX_PATH];
	WIN32_FIND_DATAW findFileData;

	lstrcpyW(directoryPath, directory);
	lstrcatW(directoryPath, L"\\*");

	HANDLE fileSearch = FindFirstFileW(directoryPath, &findFileData);

	if (fileSearch == INVALID_HANDLE_VALUE) {
		DisplayError(GetLastError());
		return;
	}

	do {
		printf("%ls\n", findFileData.cFileName);
	} while (FindNextFileW(fileSearch, &findFileData) != 0);
	
	FindClose(fileSearch);
}

void GetIpconfig(void) {

	/*
	 * Retrieve existing network adapter and IP address of the machine.
	 */

	ULONG ulFamily = AF_UNSPEC;
	ULONG ulFlags = NULL;
	VOID* reserved = NULL;
	PIP_ADAPTER_ADDRESSES pAdapterAddresses = NULL;
	ULONG ulSizePointer = NULL;
	ULONG ulRetVal;
	wchar_t ipAddrStr[INET6_ADDRSTRLEN];
	DWORD dwIpAddrStrSize = INET6_ADDRSTRLEN;
	WSADATA wsaData;
	INT wsaDataRetVal = NULL;

	// First call to get the size of the structure.
	GetAdaptersAddresses(ulFamily, ulFlags, reserved, NULL, &ulSizePointer);
	pAdapterAddresses = (PIP_ADAPTER_ADDRESSES)malloc(ulSizePointer);

	ulRetVal = GetAdaptersAddresses(ulFamily, ulFlags, reserved, pAdapterAddresses, &ulSizePointer);

	if (ulRetVal == ERROR_SUCCESS) {

		/*
		 * This startup function is required to initiates the use of Winsock DLL, 
		 * otherwise WSAAddressToStringW will not populate the buffer and you get
		 * unexpected result.
		 */
		wsaDataRetVal = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (wsaDataRetVal != 0) {
			DisplayError(wsaDataRetVal);
			return;
		}
		PIP_ADAPTER_ADDRESSES pCurrentAdapter = pAdapterAddresses;
		while (pCurrentAdapter) {
			printf("Adapter name: %ls\n", pCurrentAdapter->FriendlyName);
			PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrentAdapter->FirstUnicastAddress;
			while (pUnicast) {
				// Convert WinSock Sockaddr (IP Address, etc) structure to human-readable string
				WSAAddressToStringW(pUnicast->Address.lpSockaddr, pUnicast->Address.iSockaddrLength, NULL, ipAddrStr, &dwIpAddrStrSize);
				printf("IPv4 unicast address: %ls\n", ipAddrStr);
				pUnicast = pUnicast->Next;
			}
			printf("\n");
			pCurrentAdapter = pCurrentAdapter->Next;
		}
	}
	else {
		DisplayError(ulRetVal);
	}

	free(pAdapterAddresses);
}

int wmain(int argc, wchar_t * argv[]){

	if (argc <= 1) {
		printf("Usage: %ls [whoami|net|sysinfo|process|\"remote process\"|ls]", argv[0]);
	}
	else if (lstrcmpiW(argv[1], L"hostname") == 0) {
		GetHostname();
	}
	else if (lstrcmpiW(argv[1],L"whoami") == 0) {
		GetWhoami();
	}
	else if (lstrcmpiW(argv[1], L"sysinfo") == 0) {
		GetSysinfo();
	}
	else if (lstrcmpiW(argv[1], L"hotfixes") == 0) {
		GetHotfixes();
	}
	else if (lstrcmpiW(argv[1], L"process") == 0) {
		GetProcesses();
	}
	else if (lstrcmpiW(argv[1], L"remote process") == 0) {
		GetRemoteProcesses();
	}
	else if (lstrcmpiW(argv[1], L"ls") == 0) {
		if (argv[2] == NULL) {
			wchar_t buffer[MAX_PATH];
			DWORD dwBufferLength = MAX_PATH;
			GetCurrentDirectoryW(dwBufferLength, buffer);
			GetDirectoryList(buffer);
		}
		else {
			GetDirectoryList(argv[2]);
		}
	}
	else if (lstrcmpiW(argv[1], L"net") == 0) {
		if (lstrcmpiW(argv[2], L"users") == 0) {
			printf("Enumerate local machine users:\n");
			GetUsers();
		}
		else if (lstrcmpiW(argv[2], L"user") == 0) {
			GetUserInfo(argv[3]);
		}
	}
	else if (lstrcmpiW(argv[1], L"ipconfig") == 0) {
		GetIpconfig();
	}

	return 0;

}