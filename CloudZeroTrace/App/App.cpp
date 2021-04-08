#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <pwd.h>

#include "App.h"
#include "Globals.h"

#define MAX_PATH FILENAME_MAX

LocalStorage *ls;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* OCALL functions */

void ocall_print_string(const char *str) {
    printf("%s", str);
}

void ocall_print_character(const char *c) {
        printf("%c", *c);
}

void ocall_print_uint(uint64_t i) {
    printf("%lu", i);
}

uint8_t ocall_uploadBucket(unsigned char* serialized_bucket, uint32_t bucket_size, uint32_t label, unsigned char* hash, uint32_t hash_size, uint32_t size_for_level, uint8_t recursion_level) {
    ls->uploadBucket(label, serialized_bucket, size_for_level, hash, hash_size, recursion_level);
    return 0;
}

uint8_t ocall_uploadPath(unsigned char* path_array, uint32_t path_size, uint32_t leaf_label, unsigned char* path_hash, uint32_t path_hash_size, uint8_t level, uint32_t D_level) {
    // Real path should be printed by printing path_array because i don't encrypt path

    ls->uploadPath(leaf_label, path_array, path_hash, level, D_level);
    return 0;
}

uint8_t ocall_downloadBucket(unsigned char* serialized_bucket, uint32_t bucket_size, uint32_t label, unsigned char* hash, uint32_t hash_size, uint32_t size_for_level, uint8_t recursion_level) {
    ls->downloadBucket(label, serialized_bucket, size_for_level, hash, hash_size, recursion_level);
    return 0;
}

uint8_t ocall_downloadPath(unsigned char* path_array, uint32_t path_size, uint32_t leaf_label, unsigned char *path_hash, uint32_t path_hash_size, uint8_t level, uint32_t D_level) {
    ls->downloadPath(leaf_label, path_array, path_hash, path_hash_size, level, D_level);
    return 0;
}

void ocall_buildFetchChildHash(uint32_t left, uint32_t right, unsigned char* lchild, unsigned char* rchild, uint32_t hash_size, uint32_t recursion_level) {
    ls->fetchHash(left, lchild, hash_size, recursion_level);
    ls->fetchHash(right, rchild, hash_size, recursion_level);
}


/* functions... */
uint8_t computeRecursionLevels(uint32_t max_blocks, uint32_t recursion_data_size, uint64_t onchip_posmap_memory_limit) {
    uint8_t recursion_levels = 1;
    uint8_t x;

    if(recursion_data_size!=0) {		
        recursion_levels = 1;
        x = recursion_data_size / sizeof(uint32_t);
        uint64_t size_pmap0 = max_blocks * sizeof(uint32_t);
        uint64_t cur_pmap0_blocks = max_blocks;

        while(size_pmap0 > onchip_posmap_memory_limit) {
            cur_pmap0_blocks = (uint64_t) ceil((double)cur_pmap0_blocks/(double)x);
            recursion_levels++;
            size_pmap0 = cur_pmap0_blocks * sizeof(uint32_t);
        }
    }

    return recursion_levels;
}

uint32_t OC_New(uint32_t max_blocks, uint32_t data_size, uint32_t stash_size, uint32_t recursion_data_size, uint8_t pZ) {
    sgx_status_t sgx_return = SGX_SUCCESS;
    uint8_t ret;
    int8_t recursion_levels;

    ls = new LocalStorage(); 

    recursion_levels = computeRecursionLevels(max_blocks, recursion_data_size, MEM_POSMAP_LIMIT);
    
    uint32_t D = (uint32_t)ceil(log((double)max_blocks/pZ) / log((double)2));
    ls->setParams(max_blocks, D, pZ, stash_size, data_size + ADDITIONAL_METADATA_SIZE, recursion_data_size + ADDITIONAL_METADATA_SIZE, recursion_levels);
    
    sgx_return = ecall_createNewORAM(global_eid, &ret, max_blocks, data_size, stash_size, recursion_data_size, recursion_levels, pZ);
    
    if(sgx_return == SGX_SUCCESS) 
        return 1;
    else {
        print_error_message(sgx_return);
        return 0;
    }
}

uint32_t OC_Access(unsigned char *encrypted_request, unsigned char *encrypted_response, unsigned char *tag_in, unsigned char* tag_out, uint32_t request_size, uint32_t response_size, uint32_t tag_size) {
    sgx_status_t sgx_return = SGX_SUCCESS;
    uint8_t ret;

    sgx_return = ecall_accessInterface(global_eid, encrypted_request, encrypted_response, tag_in, tag_out, request_size, response_size, tag_size);
    if(sgx_return == SGX_SUCCESS) 
        return 1;
    else {
        print_error_message(sgx_return);
        return 0;
    }
}

/* Application entry */
int main(int argc, char *argv[]) {
    sgx_launch_token_t token = {0};
    int updated, ret;
    sgx_status_t ecall_status, enclave_status;

#ifdef OC_DEBUG
    printf("Debug - ON\n");
    printf("----- initialize -----\n\n");
#endif

    enclave_status = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if(enclave_status != SGX_SUCCESS) {
        print_error_message(enclave_status);
        return 0;
    } 

#ifdef OC_DEBUG
    printf("[Untrusted/App] Enclave successfully created\n");
#endif
    /* Utilize edger8r attributes */
    edger8r_array_attributes();    
    edger8r_pointer_attributes();
    edger8r_type_attributes();
    edger8r_function_attributes();
    
    /* Utilize trusted libraries */
    ecall_libc_functions();
    ecall_libcxx_functions();
    ecall_thread_functions();  
    
    uint32_t oblivious_cache = OC_New(MAX_BLOCKS, DATA_SIZE, PARAM_STASH_SIZE, RECURSION_DATA_SIZE, SIZE_Z);
    
    //RandomRequestSource reqsource;
    //uint32_t *rs = reqsource.GenerateRandomSequence(REQUEST_LENGTH,MAX_BLOCKS-1);

    unsigned char rw;
    uint32_t encrypted_request_size;
    //request_size = ID_SIZE_IN_BYTES + DATA_SIZE;
    request_size = MAX_DID_SIZE + DATA_SIZE;
    response_size = DATA_SIZE;

    tag_in = (unsigned char *)malloc(TAG_SIZE);
    tag_out = (unsigned char *)malloc(TAG_SIZE);
    did = (unsigned char*)malloc(MAX_DID_SIZE + 1);
    data_in = (unsigned char *)malloc(DATA_SIZE + 1);
    data_dummy = (unsigned char *)("dummydiddummydiddummydiddummydid");
    data_out = (unsigned char *)malloc(DATA_SIZE + 1);

    encrypted_request_size = computeCiphertextSize(DATA_SIZE);
    encrypted_request = (unsigned char *)malloc(encrypted_request_size);				
    encrypted_response = (unsigned char *)malloc(response_size);    

    for(uint8_t i = 0; i < REQUEST_LENGTH; i++) {
#ifdef OC_DEBUG    
        printf("\n----- Access [%d] -----\n\n", i);
#endif
        printf("[Untrusted/App] Select operation(w = write, r = read): ");
        rw = fgetc(stdin);
        fgetc(stdin);

        printf("[Untrusted/App] Input did: ");
        fgets((char *)did, MAX_DID_SIZE + 1, stdin);
        fgetc(stdin);

        if(rw == 'w') {
            printf("[Untrusted/App] Input did_docs: ");
            fgets((char *)data_in, DATA_SIZE + 1, stdin);
            fgetc(stdin);
        }
        else {
            memcpy(data_in, data_dummy, DATA_SIZE + 1);
        }

        //encryptRequest(8, rw, data_in, DATA_SIZE, encrypted_request, tag_in, encrypted_request_size);
        encryptRequest(did, rw, data_in, DATA_SIZE, encrypted_request, tag_in, encrypted_request_size);
#ifdef OC_DEBUG
        printf("\n[Untrusted/App] Request successfully encrypted\n");
        printf("[Untrusted/App] Querying encrypted request\n");
#endif
        OC_Access(encrypted_request, encrypted_response, tag_in, tag_out, encrypted_request_size, response_size, TAG_SIZE);
#ifdef OC_DEBUG
        printf("[Untrusted/App] Decrypting response\n");
#endif
        extractResponse(encrypted_response, tag_out, response_size, data_out);
        data_out[DATA_SIZE] = '\0';
#ifdef OC_DEBUG
        printf("[Untrusted/App] Response successfully decrypted\n");
        printf("[Untrusted/App] response: %s\n", data_out);
#endif
        memset(data_out, 0x00, DATA_SIZE);
    }

#ifdef OC_DEBUG
    printf("\n----- finalize -----\n\n");
#endif

    free(encrypted_request);
    free(encrypted_response);
    free(tag_in);
    free(tag_out);
    free(data_in);
    free(data_out);

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

#ifdef OC_DEBUG
        printf("[Untrusted/App] Enclave successfully destroyed\n\n");
#endif
    return 0;
}