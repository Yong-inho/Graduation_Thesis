#ifndef __ENCLAVE_UTILS_HPP__
#define __ENCLAVE_UIILS_HPP__

#include "sgx_tcrypto.h"
#include "../../global_config.h"
#include "oasm_lib.h"

//void printf(const char *fmt, ...);

void oarraySearch(uint32_t *array, uint32_t loc, uint32_t *leaf, uint32_t newLabel, uint32_t N_level);

#endif