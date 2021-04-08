#ifndef __STASH_HPP__
#define __STASH_HPP__

#include "Enclave_utils.hpp"

struct nodev2 {
    unsigned char *serialized_block;
    struct nodev2 *next;
};

// Stash is just linked list!
class Stash {
    private:
        struct nodev2 *start;
        uint32_t current_size;
        uint32_t stash_data_size;
        uint32_t STASH_SIZE; // maximum stash size!
        uint64_t gN;
    public:
        Stash();

        void setup(uint32_t stash_size, uint32_t data_size, uint32_t gN);
        void insertNewBlock();
        struct nodev2 *getStart(); //start means starting point of stash(which is a kind of list)
        void setStart(struct nodev2 *new_start);

        void performAccessOperation(char op_type, uint32_t id, uint32_t newleaf, unsigned char *data_in, unsigned char *data_out);

        void passInsert(unsigned char *serialized_block, bool is_dummy);

        // Debug
        uint32_t stashOccupancy();
        uint32_t displayStashContents(uint64_t nlevel, bool recursive_block);

        /* unused
        Stash(uint32_t STASH_SIZE, uint32_t data_size, uint32_t gN);
        void setParams(uint32_t param_stash_data_size, uint32_t param_STASH_SIZE, uint32_t param_gN);               
        void remove(nodev2 *ptr, nodev2 *prev_ptr);
        void insert(unsigned char *serialized_block);
        */
};

#endif