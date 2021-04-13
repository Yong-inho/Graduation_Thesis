#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <pwd.h>

#include "utils.h"

#include "sgx_urts.h"     /* sgx_enclave_id_t */
#include "Enclave_u.h"

sgx_enclave_id_t global_eid;

/***** mbedtls *****/
#include "mbedtls/error.h"
#include "mbedtls/net.h"
#include "mbedtls/ssl.h"

#include "mbedtls_net.c"

#include "ssl_context.h"

#define mbedtls_fprintf fprintf
#define mbedtls_printf printf
#define mbedtls_snprintf snprintf

/***** thread *****/
#include <pthread.h>
#include <thread>
#define MAX_NUM_THREADS 10

typedef struct {
    int active;
    thread_info_t data;
    pthread_t thread;
} pthread_info_t;

static pthread_info_t threads[MAX_NUM_THREADS];

/***** Cache *****/
#include "LocalStorage.hpp"
LocalStorage *ls;

/***** OCALL functions *****/
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


/***** functions... *****/
uint8_t compute_recursion_levels(uint32_t max_blocks, uint32_t recursion_data_size, uint64_t onchip_posmap_memory_limit) {
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

void *ssl_connection_handler(void *data)
{
    unsigned long thread_id = pthread_self();
    thread_info_t *thread_info = (thread_info_t *)data;

    sleep(2);

    ecall_ssl_connection_handler(global_eid, thread_id, thread_info);    

    mbedtls_net_free(&thread_info->client_fd);
    return (NULL);
}

static int thread_create(mbedtls_net_context *client_fd)
{
    int ret, i;

    for (i = 0; i < MAX_NUM_THREADS; i++) {
        if (threads[i].active == 0)
            break;

        // wait for termination and clean it up
        if (threads[i].data.thread_complete == 1) {
            pthread_join(threads[i].thread, NULL);
            memset(&threads[i], 0, sizeof(pthread_info_t));
            break;
        }
    }

    if (i == MAX_NUM_THREADS)
        return (-1);

    threads[i].active = 1;
    threads[i].data.config = NULL;
    threads[i].data.thread_complete = 0;
    memcpy(&threads[i].data.client_fd, client_fd, sizeof(mbedtls_net_context));

    if ((ret = pthread_create(&threads[i].thread, NULL, ssl_connection_handler, &threads[i].data)) != 0) {
        return (ret);
    }

    return (0);
}

sgx_status_t czt_create_oram(uint32_t max_blocks, uint32_t data_size, uint32_t stash_size, uint32_t recursion_data_size, uint8_t pZ) {
    sgx_status_t sgx_return = SGX_SUCCESS;
    uint8_t ret;
    int8_t recursion_levels;

    ls = new LocalStorage(); 

    recursion_levels = compute_recursion_levels(max_blocks, recursion_data_size, MEM_POSMAP_LIMIT);
    
    uint32_t D = (uint32_t)ceil(log((double)max_blocks/pZ) / log((double)2));
    ls->setParams(max_blocks, D, pZ, stash_size, data_size + ADDITIONAL_METADATA_SIZE, recursion_data_size + ADDITIONAL_METADATA_SIZE, recursion_levels);
    
    sgx_return = ecall_createNewORAM(global_eid, &ret, max_blocks, data_size, stash_size, recursion_data_size, recursion_levels, pZ);
    sgx_return = ecall_ssl_conn_init(global_eid);
    
    return sgx_return;
}

/***** Application entry point *****/
int main(void) {
    int ret;

#ifdef OC_DEBUG
    printf("Debug - ON\n");
    printf("----- initialize -----\n\n");
#endif

    /***** initialize SGX *****/    
    if (0 != initialize_enclave(&global_eid)) {
        exit(-1);
    }

#ifdef OC_DEBUG
    printf("[Untrusted/App] Enclave successfully created\n");
#endif

    /***** initialize CZT *****/    
    czt_create_oram(MAX_BLOCKS, DATA_SIZE, PARAM_STASH_SIZE, RECURSION_DATA_SIZE, SIZE_Z);
    
    /***** initialize threads *****/
    memset(threads, 0, sizeof(threads));

    /***** initialize mbedtls *****/
    mbedtls_net_context listen_fd, client_fd;
    ecall_ssl_conn_init(global_eid);    

    if ((ret == mbedtls_net_bind(&listen_fd, NULL, "4433", MBEDTLS_NET_PROTO_TCP)) != 0) {
        printf(" failed\n ! mbedtls_net_bind returned %d\n\n", ret);
        std::exit(-1);
    }

    while(true) {
        if(mbedtls_net_set_nonblock(&listen_fd) != 0)
            printf(" failed\n ! can't set nonblock for the listend socket\n");
        
        ret = mbedtls_net_accept(&listen_fd, &client_fd, NULL, 0, NULL);
        if(ret == MBEDTLS_ERR_SSL_WANT_READ) {
            ret = 0;
            continue;
        } else if(ret != 0) {
            printf(" failed\n ! mbedtls_net_accept returned -0x%04x\n", ret);
            break;
        }

        if ((ret = thread_create(&client_fd)) != 0)
        {
            printf("  [ main ]  failed: thread_create returned %d\n", ret);
            mbedtls_net_free(&client_fd);
            continue;
        }
        ret = 0;
    }

#ifdef OC_DEBUG
    printf("\n----- finalize -----\n\n");
#endif

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

#ifdef OC_DEBUG
        printf("[Untrusted/App] Enclave successfully destroyed\n\n");
#endif

    return 0;
}