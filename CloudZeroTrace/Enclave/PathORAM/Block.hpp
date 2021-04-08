#ifndef __BLOCKS_HPP__
#define __BLOCKS_HPP__

#include "../../global_config.h"
#include "Enclave_utils.hpp"

#include "sgx_trts.h"
#include "Enclave_t.h"

class Block {
    public:
        unsigned char *data; // data = did_docs
        uint32_t id; // block id
        uint32_t tree_label; // ??
        uint8_t *r; // ?
        
        Block(uint32_t data_size, uint32_t gN);
        void generate_data(uint32_t data_size);
        void generate_r();
        
        void initialize(uint32_t data_size, uint32_t gN);

        void reset(uint32_t data_size, uint32_t gN);

        void fill_recursion_data(uint32_t *pmap, uint32_t recursion_data_size);

        unsigned char *serialize(uint32_t data_size);
        void aes_enc(uint32_t data_size, unsigned char *aes_key);
        void serializeForAes(unsigned char *buffer, uint32_t bData_size);

        /* unused..
        Block();
        Block(uint32_t gN);
        Block(Block &b, uint32_t g_data_size);
        Block(uint32_t p_id, uint8_t *p_data, uint32_t p_label); // p_ = parameter
        Block(unsigned char *serialized_block, uint32_t block_data_size);
        ~Block();

        void initialize(uint32_t data_size, uint32_t gN);
        bool isDummy(uint32_t gN);

        //void fill();
        //void fill(uint32_t data_size);
        void fill(unsigned char *serialized_block, uint32_t data_size);

        void serializeToBuffer(unsigned char *serialized_block, uint32_t data_size);

        void aes_dec(uint32_t data_size, unsigned char *aes_key);
        */
};

#endif