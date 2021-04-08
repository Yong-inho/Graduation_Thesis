#ifndef __BUCKET_HPP__
#define __BUCKET_HPP__

#include "Enclave_utils.hpp"
#include "Block.hpp"

class Bucket {
    public:
        Block *blocks;
        uint8_t Z;

        Bucket(uint8_t Z);
        
        void initialize(uint32_t data_size, uint32_t gN);
        void reset_blocks(uint32_t data_size, uint32_t gN);

        unsigned char *serialize(uint32_t data_size);

        void aes_encryptBlocks(uint32_t data_size, unsigned char *aes_key);

        /* unused...
        Bucket(unsigned char *serialized_bucket, uint32_t data_size, uint8_t Z);
        ~Bucket();
    
        void fill(Block *b, uint32_t pos, uint32_t g_data_size);
        void fill(unsigned char *serialized_block, uint32_t pos, uint32_t g_data_size);        

        void aes_decryptBlocks(uint32_t data_size, unsigned char *aes_key);

        void serializedToBuffer(unsigned char *serializeBuffer, uint32_t data_size);
        */
};

#endif