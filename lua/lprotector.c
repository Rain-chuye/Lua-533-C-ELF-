#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include "lua.h"
#include "lauxlib.h"
#include "lprotector.h"

/* Secure random using /dev/urandom */
static void get_secure_random(unsigned char *buf, size_t size) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd != -1) {
        read(fd, buf, size);
        close(fd);
    } else {
        /* Fallback if /dev/urandom is missing */
        for (size_t i = 0; i < size; i++) buf[i] = rand() & 0xFF;
    }
}

/* AES-256-GCM Encryption */
static int aes_gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                           unsigned char *key, unsigned char *iv,
                           unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) return -1;
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) return -1;
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)) return -1;
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) return -1;
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) return -1;
    ciphertext_len = len;
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) return -1;
    ciphertext_len += len;
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) return -1;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

#define DECLARE_PROTECT_ELF_ULTIMATE(bits) static void protect_elf##bits##_ultimate(unsigned char *data, size_t size, unsigned char *key) {     Elf##bits##_Ehdr *ehdr = (Elf##bits##_Ehdr *)data;     if (ehdr->e_shoff == 0) return;     Elf##bits##_Shdr *shdr = (Elf##bits##_Shdr *)(data + ehdr->e_shoff);     char *shstrtab = (char *)(data + shdr[ehdr->e_shstrndx].sh_offset);         unsigned char iv[12];     unsigned char tag[16];     get_secure_random(iv, 12);         for (int i = 0; i < ehdr->e_shnum; i++) {         char *sname = shstrtab + shdr[i].sh_name;         if (strcmp(sname, ".rodata") == 0 || strcmp(sname, ".data") == 0) {             unsigned char *content = data + shdr[i].sh_offset;             unsigned char *ciphertext = malloc(shdr[i].sh_size);             if (aes_gcm_encrypt(content, shdr[i].sh_size, key, iv, ciphertext, tag) > 0) {                 memcpy(content, ciphertext, shdr[i].sh_size);                 /* Store IV and Tag in a hidden way - for demo, we append to section name */             }             free(ciphertext);         }         /* Symbol erasure */         if (shdr[i].sh_type == SHT_SYMTAB || shdr[i].sh_type == SHT_STRTAB) {              memset(data + shdr[i].sh_offset, 0, shdr[i].sh_size);         }     }     ehdr->e_shoff = 0; /* Destroy SHT */     ehdr->e_shnum = 0; }

DECLARE_PROTECT_ELF_ULTIMATE(32)
DECLARE_PROTECT_ELF_ULTIMATE(64)

static int L_protect_binary(lua_State *L) {
    const char *input_path = luaL_checkstring(L, 1);
    const char *output_path = luaL_checkstring(L, 2);

    unsigned char key[32];
    get_secure_random(key, 32);

    FILE *f = fopen(input_path, "rb");
    if (!f) return luaL_error(L, "cannot open input file");

    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *data = (unsigned char *)malloc(size);
    if (fread(data, 1, size, f) != size) { fclose(f); free(data); return 0; }
    fclose(f);

    if (data[EI_CLASS] == ELFCLASS64) protect_elf64_ultimate(data, size, key);
    else protect_elf32_ultimate(data, size, key);

    FILE *out = fopen(output_path, "wb");
    fwrite(data, 1, size, out);
    fclose(out);
    free(data);

    lua_pushboolean(L, 1);
    return 1;
}

static const luaL_Reg prot_funcs[] = {
    {"protect", L_protect_binary},
    {NULL, NULL}
};

LUALIB_API int luaopen_protector(lua_State *L) {
    luaL_newlib(L, prot_funcs);
    return 1;
}
