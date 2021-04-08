#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdlib.h>
#include <stdint.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>

#include "../global_config.h"

uint32_t computeCiphertextSize(uint32_t data_size);

int AES_GCM_128_encrypt (unsigned char *plaintext, int plaintext_len, unsigned char *aad,
        int aad_len, unsigned char *key, unsigned char *iv, int iv_len,
        unsigned char *ciphertext, unsigned char *tag);
int AES_GCM_128_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
        int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
        int iv_len, unsigned char *plaintext);

//int encryptRequest(int request_id, char op_type, unsigned char *data, uint32_t data_size, unsigned char *encrypted_request, unsigned char *tag, uint32_t request_size);
int encryptRequest(unsigned char *did, char op_type, unsigned char *data, uint32_t data_size, unsigned char *encrypted_request, unsigned char *tag, uint32_t request_size);
int extractResponse(unsigned char *encrypted_response, unsigned char *tag, int response_size, unsigned char *data_out);

void serializeRequest(unsigned char *did, char op_type, unsigned char *data, uint32_t data_size, unsigned char* serialized_request);

#endif