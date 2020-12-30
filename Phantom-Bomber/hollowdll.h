#pragma once
#include "helper.h"

//Perform txf/phantom DLL hollowing or regular DLL hollowing for provided shellcode
bool HollowDLL(uint8_t** ppMapBuf, uint64_t* pqwMapBufSize, const uint8_t* pCodeBuf, uint32_t dwReqBufSize, uint8_t** ppMappedCode, uint8_t** pprMapBuf, uint8_t** pprMappedCode, uint64_t rrpid, bool bTxF, bool vvp_to_rx);
