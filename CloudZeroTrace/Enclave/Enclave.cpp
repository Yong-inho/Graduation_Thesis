#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "ssl_handler.hpp"
#include "PathORAM.hpp"
#include "../global_config.h"

#include "Enclave_t.h"
#include "Enclave.h"

PathORAM *poram;
TLSConnectionHandler *connectionHandler;
sgx_thread_mutex_t mutex;

void ecall_ssl_conn_init(void)
{
    connectionHandler = new TLSConnectionHandler();
}

uint8_t ecall_createNewORAM(uint32_t max_blocks, uint32_t data_size, uint32_t stash_size, uint32_t recursion_data_size, int8_t recursion_levels, uint8_t Z){
    poram = new PathORAM();

    poram->Create(Z, max_blocks, data_size, stash_size, recursion_data_size, recursion_levels);

    sgx_thread_mutex_init(&mutex, NULL);

#ifdef OC_DEBUG
    ocall_status = ocall_print_string("\t[Trusted/Enclave] PathORAM successfully created\n");
#endif

    return 0;
}

void ecall_ssl_connection_handler(long int thread_id, thread_info_t *thread_info)
{
    connectionHandler->handle(thread_id, thread_info, poram, &mutex);
}