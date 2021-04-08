#ifndef __GLOBALS_H__
#define __GLOBALS_H__

#include <math.h>

#include "utils.h"
#include "LocalStorage/LocalStorage.hpp"

#include "sgx_urts.h"     /* sgx_enclave_id_t */
#include "Enclave_u.h"

sgx_enclave_id_t global_eid = 0;

//uint32_t DATA_SIZE = 4; // did_docs
//uint32_t MAX_BLOCKS = 128;
//uint32_t STASH_SIZE = 150; // It is typically sufficient to use 150 for PathORAM
//uint32_t RECURSION_DATA_SIZE = 64; // recursion_data_size can be used to tailor the data size of the recursive ORAM trees, since currently OC uses ids of 4 bytes, recursion sie of 64, gives us a compression factor 16 with each level of recrusion.
//int REQUEST_LENGTH = 2;
//uint8_t Z = 4; // Z is the number of blocks in a bucket of the ORAMTree, typically PathORAM uses Z=4

unsigned char *encrypted_request, *tag_in, *encrypted_response, *tag_out;
uint32_t request_size, response_size;
unsigned char *did;
unsigned char *data_in;
unsigned char *data_dummy;
unsigned char *data_out;

#endif
