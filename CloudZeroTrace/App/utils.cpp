#include "utils.h"

int encryptRequest(unsigned char *did, /*int request_id,*/ char op_type, unsigned char *data, uint32_t data_size, unsigned char *encrypted_request, unsigned char *tag, uint32_t request_size){
  int encrypted_request_size;	
  unsigned char *iv = (unsigned char *)malloc(IV_LENGTH); // Sample IV;
  unsigned char *serialized_request = (unsigned char*)malloc(1 + ID_SIZE_IN_BYTES + data_size); // 1 from op_type

#ifdef OC_DEBUG
  printf("\n[Untrusted/App] Encrypting request: [%c]\n", op_type);
  printf("[Untrusted/App] DID: ");
  for(int i = 0; i < MAX_DID_SIZE; i++)
      printf("%c", did[i]);  
  //printf("%d", request_id);
  printf("\n");
  printf("[Untrusted/App] DID_docs: ");
  for(int i = 0; i < data_size; i++)
      printf("%c", data[i]);
  printf("\n");
#endif

  //serializeRequest(request_id, op_type, data, data_size, serialized_request);
  serializeRequest(did, op_type, data, data_size, serialized_request);

  encrypted_request_size = AES_GCM_128_encrypt(serialized_request, request_size, NULL, 0, (unsigned char*) SHARED_AES_KEY, (unsigned char*) HARDCODED_IV, IV_LENGTH, encrypted_request, tag);
  
  free(serialized_request);
  free(iv);
  
  return encrypted_request_size;
}

int extractResponse(unsigned char *encrypted_response, unsigned char *tag, int response_size, unsigned char *data_out) {
  AES_GCM_128_decrypt(encrypted_response, response_size, NULL, 0, tag, (unsigned char*) SHARED_AES_KEY, (unsigned char*) HARDCODED_IV, IV_LENGTH, data_out);
  return response_size;
}

void serializeRequest(unsigned char *did, /*request_id,*/ char op_type, unsigned char *data, uint32_t data_size, unsigned char* serialized_request){
  unsigned char *request_ptr = serialized_request;

  *request_ptr=op_type;
  request_ptr += 1;
  memcpy(request_ptr, did, MAX_DID_SIZE);
  request_ptr +=  MAX_DID_SIZE;	
  memcpy(request_ptr, data, data_size);
}

uint32_t computeCiphertextSize(uint32_t data_size){
  //Rounded up to nearest block size:
  uint32_t encrypted_request_size;
  //encrypted_request_size = ((1+ID_SIZE_IN_BYTES+data_size) / AES_GCM_BLOCK_SIZE_IN_BYTES);
  encrypted_request_size = ((1+MAX_DID_SIZE+data_size) / AES_GCM_BLOCK_SIZE_IN_BYTES);


  if((MAX_DID_SIZE+data_size)%AES_GCM_BLOCK_SIZE_IN_BYTES!=0)
    encrypted_request_size+=1;

  encrypted_request_size*=16;

  return encrypted_request_size;
}

int AES_GCM_128_encrypt (unsigned char *plaintext, int plaintext_len, unsigned char *aad,
  int aad_len, unsigned char *key, unsigned char *iv, int iv_len,
  unsigned char *ciphertext, unsigned char *tag)
{
  EVP_CIPHER_CTX *ctx;

  int len;
  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) {
    printf("Failed context intialization for OpenSSL EVP\n");
  }

  /* Initialise the encryption operation. */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)){
    printf("Failed AES_GCM_128 intialization for OpenSSL EVP\n");	
  }

  /* Set IV length if default 12 bytes (96 bits) is not appropriate */
  if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)){
    printf("Failed IV config\n");
  }

  /* Initialise key and IV */
  if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
    printf("Failed intialization for key and IV for AES_GCM\n");	
  }

  /* Provide any AAD data. This can be called zero or more times as
   * required
   */
  //if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
  //	printf("Failed AAD\n");

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  //printf("Error code = %d\n\n", EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len));
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
    printf("Failed AES_GCM encrypt\n");
  }
  ciphertext_len = len;

  /* Finalise the encryption. Normally ciphertext bytes may be written at
   * this stage, but this does not occur in GCM mode
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)){
    printf("Failed Finalizing ciphertext\n");	
  }
  ciphertext_len += len;

  /* Get the tag */
  if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag))
    printf("Failed tag for AES_GCM_encrypt\n");

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int AES_GCM_128_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
  int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
  int iv_len, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  int ret;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) 
    printf("Failed context intialization for OpenSSL EVP\n");

  /* Initialise the decryption operation. */
  if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
    printf("Failed AES_GCM_128 intialization for OpenSSL EVP\n");	

  /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
  if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
    printf("Failed IV config\n");

  /* Initialise key and IV */
  if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
    printf("Failed intialization for key and IV for AES_GCM_128\n");	
  /* Provide any AAD data. This can be called zero or more times as
   * required
   */
  //if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
  //	printf("Failed AAD\n");

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    printf("Failed AES_GCM decrypt\n");
  plaintext_len = len;

  /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
  if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag))
    printf("Failed tag for AES_GCM_decrypt\n");

  /* Finalise the decryption. A positive return value indicates success,
   * anything else is a failure - the plaintext is not trustworthy.
   */
  ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  if(ret > 0)
  {
    /* Success */
    plaintext_len += len;
    return plaintext_len;
  }
  else
  {
    /* Verify failed */
    return -1;
  }
}
