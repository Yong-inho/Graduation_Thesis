#include "../global_config.h"
#include "DID_Map.hpp"
#include "PathORAM/PathORAM.hpp"

#include "Enclave_t.h"
#include "Enclave.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

PathORAM *poram;
DIDMap *DIDmap;

int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

uint8_t ecall_createNewORAM(uint32_t max_blocks, uint32_t data_size, uint32_t stash_size, uint32_t recursion_data_size, int8_t recursion_levels, uint8_t Z){
    sgx_status_t ocall_status;
    poram = new PathORAM();
    DIDmap = new DIDMap();

    poram->Create(Z, max_blocks, data_size, stash_size, recursion_data_size, recursion_levels);
    DIDmap->initialize();

#ifdef OC_DEBUG
    ocall_status = ocall_print_string("\t[Trusted/Enclave] PathORAM successfully created\n");
#endif

    return 0;
}

void ecall_accessInterface(unsigned char *encrypted_request, unsigned char *encrypted_response, unsigned char *tag_in, unsigned char *tag_out, uint32_t encrypted_request_size, uint32_t response_size, uint32_t tag_size) {
    unsigned char *did, *data_in, *data_out, *request, *request_ptr;
    int id = 0;
    unsigned char op_type;
    sgx_status_t ocall_status;
    uint8_t i;

    did = (unsigned char *)malloc(MAX_DID_SIZE);
    request = (unsigned char *)malloc(encrypted_request_size);
    data_out = (unsigned char *)malloc(response_size);

    // Decrypt request
    sgx_status_t status = SGX_SUCCESS;
    status = sgx_rijndael128GCM_decrypt((const sgx_aes_gcm_128bit_key_t *) SHARED_AES_KEY, (const uint8_t *) encrypted_request,
			    encrypted_request_size, (uint8_t *) request, (const uint8_t *) HARDCODED_IV, IV_LENGTH,
			    NULL, 0, (const sgx_aes_gcm_128bit_tag_t*) tag_in);

#ifdef OC_DEBUG
    if(status == SGX_SUCCESS) {
        ocall_print_string("\t[Trusted/Enclave] Decrypting request\n");
    } else{
    	if(status == SGX_ERROR_INVALID_PARAMETER)
	        ocall_print_string("\t[Trusted/Enclave]Decrypt returned SGX_ERROR_INVALID_PARAMETER Failure flag\n");		
	    else
		    ocall_print_string("\t[Trusted/Enclave]Decrypt returned another Failure flag\n");
    }
#endif

    // Extract request ID and optype
    op_type = request[0];
    request_ptr = request + 1;
    //memcpy(&id, request_ptr, ID_SIZE_IN_BYTES);
    memcpy(did, request_ptr, MAX_DID_SIZE);
    data_in = request_ptr + MAX_DID_SIZE;

#ifdef OC_DEBUG
    printf("\n\t[Trusted/Enclave] Decrypted request: [%c]\n", op_type);
    printf("\t[Trusted/Enclave] DID: ");
    for(i = 0; i < MAX_DID_SIZE; i++)
        printf("%c", did[i]);
    printf("\n\t[Trusted/Enclave] DID_docs: ");
    for(i = 0; i < DATA_SIZE; i++)
        printf("%c", *(data_in + i));
    printf("\n\n\t[Trusted/Enclave] Accessing oblivious cache\n");    
#endif

    id = DIDmap->convertDIDToBlockID(did, op_type);
    if(id == -1) {
        id = MAX_BLOCKS + 1;
#ifdef OC_DEBUG
        printf("\t[Trusted/Enclave] Not cached\n");
#endif
    }
    poram->Access(id, op_type, data_in, data_out);

#ifdef OC_DEBUG
    ocall_print_string("\t[Trusted/Enclave] Encrypting response\n\t[Trusted/Enclave] response: ");
    for(uint8_t i = 0; i < response_size; i++)
        ocall_print_character((const char *)(data_out+i));
    ocall_print_character("\n");
#endif

    // Encrypt Response
    status = sgx_rijndael128GCM_encrypt((const sgx_aes_gcm_128bit_key_t *) SHARED_AES_KEY, data_out, response_size,
	            (uint8_t *) encrypted_response, (const uint8_t *) HARDCODED_IV, IV_LENGTH, NULL, 0,
	            (sgx_aes_gcm_128bit_tag_t *) tag_out);

#ifdef OC_DEBUG
    ocall_print_string("\t[Trusted/Enclave] Response successfully encrypted\n");
    ocall_print_string("\t[Trusted/Encalve] Sending response\n");
#endif

    free(did);
    free(request);
    free(data_out);
}