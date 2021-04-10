#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "ssl_handler.hpp"
#include "DID_Map.hpp"
#include "PathORAM.hpp"
#include "../global_config.h"

#include "Enclave_t.h"
#include "Enclave.h"

PathORAM *poram;
DIDMap *DIDmap;
TLSConnectionHandler *connectionHandler;

void ecall_ssl_conn_init(void)
{
    connectionHandler = new TLSConnectionHandler();
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

void ecall_ssl_connection_handler(long int thread_id, thread_info_t *thread_info)
{
    connectionHandler->handle(thread_id, thread_info, poram, DIDmap);
}