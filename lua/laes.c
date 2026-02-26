#include "laes.h"
#include <string.h>

/* Robust AES implementation with alignment handling */

static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static uint32_t sub_word(uint32_t w) {
    return (sbox[w >> 24] << 24) | (sbox[(w >> 16) & 0xFF] << 16) |
           (sbox[(w >> 8) & 0xFF] << 8) | sbox[w & 0xFF];
}

static uint32_t rot_word(uint32_t w) {
    return (w << 8) | (w >> 24);
}

int aes_setkey_encrypt(aes_context *ctx, const uint8_t *key, int keysize) {
    int i;
    uint32_t temp;
    static const uint32_t rcon[10] = {
        0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
        0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000
    };

    if (keysize != 256) return -1;
    ctx->nr = 14;

    for (i = 0; i < 8; i++) {
        ctx->eK[i] = ((uint32_t)key[i * 4] << 24) | ((uint32_t)key[i * 4 + 1] << 16) |
                     ((uint32_t)key[i * 4 + 2] << 8) | (uint32_t)key[i * 4 + 3];
    }

    for (i = 8; i < 60; i++) {
        temp = ctx->eK[i - 1];
        if (i % 8 == 0) {
            temp = sub_word(rot_word(temp)) ^ rcon[i / 8 - 1];
        } else if (i % 8 == 4) {
            temp = sub_word(temp);
        }
        ctx->eK[i] = ctx->eK[i - 8] ^ temp;
    }
    return 0;
}

static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi_bit_set = a & 0x80;
        a <<= 1;
        if (hi_bit_set) a ^= 0x1B;
        b >>= 1;
    }
    return p;
}

static void mix_columns(uint8_t *state) {
    uint8_t tmp[16];
    for (int i = 0; i < 4; i++) {
        tmp[i * 4] = gmul(2, state[i * 4]) ^ gmul(3, state[i * 4 + 1]) ^ state[i * 4 + 2] ^ state[i * 4 + 3];
        tmp[i * 4 + 1] = state[i * 4] ^ gmul(2, state[i * 4 + 1]) ^ gmul(3, state[i * 4 + 2]) ^ state[i * 4 + 3];
        tmp[i * 4 + 2] = state[i * 4] ^ state[i * 4 + 1] ^ gmul(2, state[i * 4 + 2]) ^ gmul(3, state[i * 4 + 3]);
        tmp[i * 4 + 3] = gmul(3, state[i * 4]) ^ state[i * 4 + 1] ^ state[i * 4 + 2] ^ gmul(2, state[i * 4 + 3]);
    }
    memcpy(state, tmp, 16);
}

void aes_encrypt(aes_context *ctx, const uint8_t *input, uint8_t *output) {
    uint8_t state[16];
    memcpy(state, input, 16);

    for (int r = 0; r <= ctx->nr; r++) {
        for (int i = 0; i < 4; i++) {
            uint32_t w = ctx->eK[r * 4 + i];
            state[i * 4] ^= (w >> 24);
            state[i * 4 + 1] ^= (w >> 16) & 0xFF;
            state[i * 4 + 2] ^= (w >> 8) & 0xFF;
            state[i * 4 + 3] ^= w & 0xFF;
        }
        if (r == ctx->nr) break;
        for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];
        uint8_t t;
        t = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t;
        t = state[2]; state[2] = state[10]; state[10] = t; t = state[6]; state[6] = state[14]; state[14] = t;
        t = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t;
        if (r < ctx->nr - 1) mix_columns(state);
    }
    memcpy(output, state, 16);
}

static void gcm_ghash(const uint8_t *h, const uint8_t *x, uint8_t *y) {
    for (int i = 0; i < 16; i++) y[i] ^= x[i];
    uint8_t res[16] = {0};
    uint8_t v[16];
    memcpy(v, h, 16);
    for (int i = 0; i < 128; i++) {
        if (y[i >> 3] & (1 << (7 - (i & 7)))) {
            for (int j = 0; j < 16; j++) res[j] ^= v[j];
        }
        uint8_t b = v[15] & 1;
        for (int j = 15; j > 0; j--) v[j] = (v[j] >> 1) | (v[j - 1] << 7);
        v[0] >>= 1;
        if (b) v[0] ^= 0xe1;
    }
    memcpy(y, res, 16);
}

void gcm_init(gcm_context *ctx, const uint8_t *key) {
    aes_setkey_encrypt(&ctx->aes_ctx, key, 256);
    uint8_t zero[16] = {0};
    aes_encrypt(&ctx->aes_ctx, zero, ctx->H);
}

int gcm_encrypt(gcm_context *ctx, const uint8_t *iv, size_t iv_len,
                const uint8_t *plaintext, size_t length,
                uint8_t *ciphertext, uint8_t *tag) {
    uint8_t ctr[16] = {0};
    if (iv_len == 12) {
        memcpy(ctr, iv, 12);
        ctr[15] = 1;
    } else return -1;

    uint8_t e_ctr0[16];
    aes_encrypt(&ctx->aes_ctx, ctr, e_ctr0);

    uint8_t y[16] = {0};
    size_t i;
    for (i = 0; i < length; i += 16) {
        ctr[15]++; if (ctr[15] == 0) ctr[14]++;
        uint8_t e_ctr[16];
        aes_encrypt(&ctx->aes_ctx, ctr, e_ctr);
        size_t block_len = (length - i < 16) ? (length - i) : 16;
        for (size_t j = 0; j < block_len; j++) ciphertext[i + j] = plaintext[i + j] ^ e_ctr[j];
        uint8_t block[16] = {0};
        memcpy(block, ciphertext + i, block_len);
        gcm_ghash(ctx->H, block, y);
    }
    uint8_t len_block[16] = {0};
    uint64_t bit_len = (uint64_t)length * 8;
    for (int j = 0; j < 8; j++) len_block[15 - j] = (uint8_t)((bit_len >> (j * 8)) & 0xFF);
    gcm_ghash(ctx->H, len_block, y);
    for (int j = 0; j < 16; j++) tag[j] = y[j] ^ e_ctr0[j];
    return 0;
}
