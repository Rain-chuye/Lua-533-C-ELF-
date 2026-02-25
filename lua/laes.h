#ifndef laes_h
#define laes_h

#include <stdint.h>
#include <stddef.h>

#define AES_BLOCK_SIZE 16
#define AES_256_KEY_SIZE 32

typedef struct {
    uint32_t eK[60];
    uint32_t dK[60];
    int nr;
} aes_context;

int aes_setkey_encrypt(aes_context *ctx, const uint8_t *key, int keysize);
void aes_encrypt(aes_context *ctx, const uint8_t *input, uint8_t *output);

/* AES-GCM (Simplified for protector) */
typedef struct {
    aes_context aes_ctx;
    uint8_t H[16];
} gcm_context;

void gcm_init(gcm_context *ctx, const uint8_t *key);
int gcm_encrypt(gcm_context *ctx, const uint8_t *iv, size_t iv_len,
                const uint8_t *plaintext, size_t length,
                uint8_t *ciphertext, uint8_t *tag);

#endif
