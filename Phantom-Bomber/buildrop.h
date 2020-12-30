#pragma once
#include "helper.h"

//Build ROP chain for stack bombing
PINJECTRA_PACKET* BuildROPChain(TStrDWORD64Map& runtime_parameters, uint64_t map_size, bool is_image_backed, int exec_option, int unmap_option, bool vvp_to_rx);
