#pragma once

#define _WIN32_DCOM
#include <iostream>
#include <comdef.h>
#include <Wbemidl.h>
#include <vector>
#include <tlhelp32.h>
//#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <winternl.h>
#include <codecvt>
#include <Urlmon.h>   // URLOpenBlockingStreamW()
#include <atlbase.h>  // CComPtr
#include <map>
#include <psapi.h>
#include <processthreadsapi.h>
#include <algorithm>
extern "C" {
#include "memmem.h"
}
#pragma comment(lib, "wbemuuid.lib")



typedef struct {
	HANDLE process;
	HANDLE thread;
	DWORD pid;
	DWORD tid;
} TARGET_PROCESS;

typedef std::pair<std::string, DWORD64> TStrDWORD64Pair;
typedef std::map<std::string, DWORD64> TStrDWORD64Map;

typedef struct {
	LPVOID buffer;
	SIZE_T buffer_size;
	TStrDWORD64Map* metadata;
} PINJECTRA_PACKET;

typedef void(*fnAddr)();

typedef LONG(__stdcall* NtCreateSection_t)(HANDLE*, ULONG, void*, LARGE_INTEGER*, ULONG, ULONG, HANDLE);
typedef LONG(__stdcall* NtMapViewOfSection_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS(__stdcall* NtCreateTransaction_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LPGUID, HANDLE, ULONG, ULONG, ULONG, PLARGE_INTEGER, PUNICODE_STRING);
typedef NTSTATUS(__stdcall* NtOpenSection_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef struct PINITIAL_TEB;
typedef NTSTATUS(__stdcall* NtCreateThreadEx_t)(PHANDLE, ACCESS_MASK, LPVOID, HANDLE, LPTHREAD_START_ROUTINE, LPVOID, BOOL, ULONG, ULONG, ULONG, LPVOID);

typedef NTSTATUS(__stdcall* NtExtendSection_t)(HANDLE, PLARGE_INTEGER);

#pragma once
typedef struct _CLIENT_ID* PCLIENT_ID;

static NTSTATUS(NTAPI* NtQueueApcThread)(
	_In_ HANDLE ThreadHandle,
	_In_ PVOID ApcRoutine,
	_In_ PVOID ApcRoutineContext OPTIONAL,
	_In_ PVOID ApcStatusBlock OPTIONAL,
	//_In_ ULONG ApcReserved OPTIONAL
	_In_ __int64 ApcReserved OPTIONAL
	);

typedef NTSTATUS(WINAPI* NTQUERYINFORMATIONTHREAD)(
	HANDLE ThreadHandle,
	ULONG ThreadInformationClass,
	PVOID ThreadInformation,
	ULONG ThreadInformationLength,
	PULONG ReturnLength);

typedef NTSTATUS(WINAPI* MyRtlCreateUserThread)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits,
	IN OUT PULONG StackReserved,
	IN OUT PULONG StackCommit,
	IN PVOID StartAddress,
	IN PVOID StartParameter OPTIONAL,
	OUT PHANDLE ThreadHandle,
	OUT PCLIENT_ID ClientID);

typedef void(__stdcall* MyRtlInitUnicodeString)(
	IN PUNICODE_STRING DestinationString,
	IN __drv_aliasesMem PCWSTR SourceString
	);

typedef HANDLE(__stdcall* MyBaseGetNamedObjectDirectory)();

static HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");

static MyRtlInitUnicodeString RtlInitUnicodeString2 = (MyRtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll"), "RtlInitUnicodeString");
static NtCreateSection_t NtCreateSection = (NtCreateSection_t)GetProcAddress(hNtdll, "NtCreateSection");
static NtExtendSection_t NtExtendSection = (NtExtendSection_t)GetProcAddress(hNtdll, "NtExtendSection");
static NtMapViewOfSection_t NtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(hNtdll, "NtMapViewOfSection");
static NtCreateTransaction_t NtCreateTransaction = (NtCreateTransaction_t)GetProcAddress(hNtdll, "NtCreateTransaction");
static NtCreateThreadEx_t NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(hNtdll, "NtCreateThreadEx");


typedef struct {
	DWORD64 address;
	size_t size;
}TEXT_SECTION_INFO;

static bool CheckRelocRange(uint8_t* pRelocBuf, uint32_t dwRelocBufSize, uint32_t dwStartRVA, uint32_t dwEndRVA);
static void* GetPAFromRVA(uint8_t* pPeBuf, IMAGE_NT_HEADERS* pNtHdrs, IMAGE_SECTION_HEADER* pInitialSectHdrs, uint64_t qwRVA);

static IMAGE_SECTION_HEADER* GetContainerSectHdr(IMAGE_NT_HEADERS* pNtHdrs, IMAGE_SECTION_HEADER* pInitialSectHeader, uint64_t qwRVA) {
	for (uint32_t dwX = 0; dwX < pNtHdrs->FileHeader.NumberOfSections; dwX++) {
		IMAGE_SECTION_HEADER* pCurrentSectHdr = pInitialSectHeader;
		uint32_t dwCurrentSectSize;

		pCurrentSectHdr += dwX;

		if (pCurrentSectHdr->Misc.VirtualSize > pCurrentSectHdr->SizeOfRawData) {
			dwCurrentSectSize = pCurrentSectHdr->Misc.VirtualSize;
		}
		else {
			dwCurrentSectSize = pCurrentSectHdr->SizeOfRawData;
		}

		if ((qwRVA >= pCurrentSectHdr->VirtualAddress) && (qwRVA <= (pCurrentSectHdr->VirtualAddress + dwCurrentSectSize))) {
			return pCurrentSectHdr;
		}
	}

	return nullptr;
}

static void* GetPAFromRVA(uint8_t* pPeBuf, IMAGE_NT_HEADERS* pNtHdrs, IMAGE_SECTION_HEADER* pInitialSectHdrs, uint64_t qwRVA) {
	IMAGE_SECTION_HEADER* pContainSectHdr;

	if ((pContainSectHdr = GetContainerSectHdr(pNtHdrs, pInitialSectHdrs, qwRVA)) != nullptr) {
		uint32_t dwOffset = (qwRVA - pContainSectHdr->VirtualAddress);

		if (dwOffset < pContainSectHdr->SizeOfRawData) { // Sections can be partially or fully virtual. Avoid creating physical pointers that reference regions outside of the raw data in sections with a greater virtual size than physical.
			return (uint8_t*)(pPeBuf + pContainSectHdr->PointerToRawData + dwOffset);
		}
	}

	return nullptr;
}


static bool CheckRelocRange(uint8_t* pRelocBuf, uint32_t dwRelocBufSize, uint32_t dwStartRVA, uint32_t dwEndRVA) {
	IMAGE_BASE_RELOCATION* pCurrentRelocBlock;
	uint32_t dwRelocBufOffset, dwX;
	bool bWithinRange = false;

	for (pCurrentRelocBlock = (IMAGE_BASE_RELOCATION*)pRelocBuf, dwX = 0, dwRelocBufOffset = 0; pCurrentRelocBlock->SizeOfBlock; dwX++) {
		uint32_t dwNumBlocks = ((pCurrentRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t));
		uint16_t* pwCurrentRelocEntry = (uint16_t*)((uint8_t*)pCurrentRelocBlock + sizeof(IMAGE_BASE_RELOCATION));

		for (uint32_t dwY = 0; dwY < dwNumBlocks; dwY++, pwCurrentRelocEntry++) {
#ifdef _WIN64
#define RELOC_FLAG_ARCH_AGNOSTIC IMAGE_REL_BASED_DIR64
#else
#define RELOC_FLAG_ARCH_AGNOSTIC IMAGE_REL_BASED_HIGHLOW
#endif
			if (((*pwCurrentRelocEntry >> 12) & RELOC_FLAG_ARCH_AGNOSTIC) == RELOC_FLAG_ARCH_AGNOSTIC) {
				uint32_t dwRelocEntryRefLocRva = (pCurrentRelocBlock->VirtualAddress + (*pwCurrentRelocEntry & 0x0FFF));

				if (dwRelocEntryRefLocRva >= dwStartRVA && dwRelocEntryRefLocRva < dwEndRVA) {
					bWithinRange = true;
				}
			}
		}

		dwRelocBufOffset += pCurrentRelocBlock->SizeOfBlock;
		pCurrentRelocBlock = (IMAGE_BASE_RELOCATION*)((uint8_t*)pCurrentRelocBlock + pCurrentRelocBlock->SizeOfBlock);
	}

	return bWithinRange;
}


static TEXT_SECTION_INFO GetTextSection(HMODULE mod)
{
	// Parse a module in order to retrieve its text section

	TEXT_SECTION_INFO section_info = { 0 };
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)mod;
	PIMAGE_NT_HEADERS NtHeader;
	PIMAGE_OPTIONAL_HEADER OptionalHeader;
	PIMAGE_SECTION_HEADER SectionHeader;

	NtHeader = (PIMAGE_NT_HEADERS)((BYTE*)DosHeader + DosHeader->e_lfanew);
	OptionalHeader = (PIMAGE_OPTIONAL_HEADER)&NtHeader->OptionalHeader;
	SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
	DWORD NumberOfSections = NtHeader->FileHeader.NumberOfSections;

	for (int i = 0; i < NumberOfSections; i++)
	{
		DWORD64 SecSize = SectionHeader->SizeOfRawData;
		if (SecSize != 0)
		{
			if (!memcmp(SectionHeader->Name, ".text", 5))
			{
				section_info.address = (DWORD64)((BYTE*)SectionHeader->VirtualAddress + (DWORD64)DosHeader);
				section_info.size = SectionHeader->SizeOfRawData;
				return section_info;
			}
			else
				SectionHeader++;
		}
		else
			SectionHeader++;
	}

	return section_info;
}

static int getPID(std::wstring processName) {

	std::vector<DWORD> pids;
	std::wstring targetProcessName = processName;

	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //all processes

	PROCESSENTRY32W entry; //current process
	entry.dwSize = sizeof entry;

	if (!Process32FirstW(snap, &entry)) { //start with the first in snapshot
		return 0;
	}

	do {
		if (std::wstring(entry.szExeFile) == targetProcessName) {
			pids.push_back(entry.th32ProcessID); //name matches; add to list
		}
	} while (Process32NextW(snap, &entry)); //keep going until end of snapshot

	//for (int i(0); i < pids.size(); ++i) {
	//	std::cout << pids[i] << std::endl;
	//}
	return pids[0];
}

static std::wstring stringToWstring(const std::string& t_str)
{
	//setup converter
	typedef std::codecvt_utf8<wchar_t> convert_type;
	std::wstring_convert<convert_type, wchar_t> converter;

	//use converter (.to_bytes: wstr->str, .from_bytes: str->wstr)
	return converter.from_bytes(t_str);
}

static std::vector<DWORD64> EnumThreads(std::wstring processName)
{
	auto targetPID = getPID(processName);
	std::vector<DWORD64> results;

	HRESULT hres;

	// Step 1: --------------------------------------------------
	// Initialize COM. ------------------------------------------

	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres))
	{
		std::cout << "Failed to initialize COM library. Error code = 0x"
			<< std::hex << hres << std::endl;
		throw "Failed to init COM";
	}

	// Step 2: --------------------------------------------------
	// Set general COM security levels --------------------------

	hres = CoInitializeSecurity(
		NULL,
		-1,                          // COM authentication
		NULL,                        // Authentication services
		NULL,                        // Reserved
		RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
		RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
		NULL,                        // Authentication info
		EOAC_NONE,                   // Additional capabilities 
		NULL                         // Reserved
	);


	if (FAILED(hres))
	{
		std::cout << "Failed to initialize security. Error code = 0x"
			<< std::hex << hres << std::endl;
		CoUninitialize();
		throw "Failed to init security";
		//return 1;                    // Program has failed.
	}

	// Step 3: ---------------------------------------------------
	// Obtain the initial locator to WMI -------------------------

	IWbemLocator* pLoc = NULL;

	hres = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID*)&pLoc);

	if (FAILED(hres))
	{
		std::cout << "Failed to create IWbemLocator object."
			<< " Err code = 0x"
			<< std::hex << hres << std::endl;
		CoUninitialize();
		throw "Failed to create IWbenLocator obj";
		//return 1;                 // Program has failed.
	}

	// Step 4: -----------------------------------------------------
	// Connect to WMI through the IWbemLocator::ConnectServer method

	IWbemServices* pSvc = NULL;

	// Connect to the root\cimv2 namespace with
	// the current user and obtain pointer pSvc
	// to make IWbemServices calls.
	hres = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
		NULL,                    // User name. NULL = current user
		NULL,                    // User password. NULL = current
		0,                       // Locale. NULL indicates current
		NULL,                    // Security flags.
		0,                       // Authority (for example, Kerberos)
		0,                       // Context object 
		&pSvc                    // pointer to IWbemServices proxy
	);

	if (FAILED(hres))
	{
		std::cout << "Could not connect. Error code = 0x"
			<< std::hex << hres << std::endl;
		pLoc->Release();
		CoUninitialize();
		throw "Can't connect";
		//return 1;                // Program has failed.
	}

	// std::cout << "Connected to ROOT\\CIMV2 WMI namespace" << std::endl;


	// Step 5: --------------------------------------------------
	// Set security levels on the proxy -------------------------

	hres = CoSetProxyBlanket(
		pSvc,                        // Indicates the proxy to set
		RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
		RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
		NULL,                        // Server principal name 
		RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
		RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
		NULL,                        // client identity
		EOAC_NONE                    // proxy capabilities 
	);

	if (FAILED(hres))
	{
		std::cout << "Could not set proxy blanket. Error code = 0x"
			<< std::hex << hres << std::endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		throw "Can't set proxy blanket";
		//return 1;               // Program has failed.
	}

	// Step 6: --------------------------------------------------
	// Use the IWbemServices pointer to make requests of WMI ----

	// https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/cim-thread (parent)
	// https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-thread (what we're playing with)
	const char* queryTemplate = "SELECT * FROM Win32_Thread WHERE ProcessHandle='%d'";
	size_t szQueryTemplate = (std::strlen(queryTemplate) - 2) + sizeof(DWORD64);
	char* qBuf = new char[szQueryTemplate];
	auto retVal = sprintf_s(qBuf, szQueryTemplate, queryTemplate, targetPID);
	// std::cout << qBuf << std::endl;

	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t(qBuf),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	if (FAILED(hres))
	{
		std::cout << "Query for operating system name failed."
			<< " Error code = 0x"
			<< std::hex << hres << std::endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		throw "Query Failed";
		//return 1;               // Program has failed.
	}

	// Step 7: -------------------------------------------------
	// Get the data from the query in step 6 -------------------

	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;

	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
			&pclsObj, &uReturn);

		if (0 == uReturn)
		{
			break;
		}

		VARIANT vtProp;

		// Get the value of the Name property

		hr = pclsObj->Get(L"ProcessHandle", 0, &vtProp, 0, 0);
		auto pid = _wtoi(vtProp.bstrVal);
		VariantClear(&vtProp);

		if (pid != targetPID) {
			continue;
		}
		hr = pclsObj->Get(L"ThreadState", 0, &vtProp, 0, 0);
		// std::wcout << " ThreadState : " << vtProp.ulVal << std::endl;

		// threadstate
		// https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-thread -- waiting is 5, we want waiting.
		if (vtProp.ulVal == 5) {
			VariantClear(&vtProp);

			hr = pclsObj->Get(L"Handle", 0, &vtProp, 0, 0);
			// std::wcout << " TID : " << vtProp.bstrVal << std::endl;
			results.push_back(_wtoi(vtProp.bstrVal));
			VariantClear(&vtProp);
		}
		else {
			VariantClear(&vtProp);
		}
		pclsObj->Release();
	}

	// Cleanup
	// ========

	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();
	delete qBuf;
	return results;   // Program successfully completed.

}
