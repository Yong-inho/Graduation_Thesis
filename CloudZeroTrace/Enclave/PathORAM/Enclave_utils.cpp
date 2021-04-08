#include "Enclave_utils.hpp"
/*
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}
*/


void oarraySearch(uint32_t *array, uint32_t loc, uint32_t *leaf, uint32_t new_label, uint32_t N_level) {
    for(uint32_t i = 0; i < N_level; i++) {
        omove(i, &(array[i]), loc, leaf, new_label);
    }
    return;
}