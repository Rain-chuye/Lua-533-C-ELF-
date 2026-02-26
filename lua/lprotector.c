#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
#include "lua.h"
#include "lauxlib.h"
#include "lprotector.h"
#include "laes.h"

static void get_secure_random(unsigned char *buf, size_t size) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd != -1) {
        ssize_t res = read(fd, buf, size);
        (void)res;
        close(fd);
    } else {
        for (size_t i = 0; i < size; i++) buf[i] = (unsigned char)(rand() & 0xFF);
    }
}

#define DECLARE_PROTECT_ELF_V4(bits) static void protect_elf##bits##_v4(unsigned char *data, size_t size, unsigned char *key) {     Elf##bits##_Ehdr *ehdr = (Elf##bits##_Ehdr *)data;     if (ehdr->e_shoff == 0 || ehdr->e_shoff >= size) return;     Elf##bits##_Shdr *shdr = (Elf##bits##_Shdr *)(data + ehdr->e_shoff);     if (ehdr->e_shstrndx >= ehdr->e_shnum) return;     char *shstrtab = (char *)(data + shdr[ehdr->e_shstrndx].sh_offset);         gcm_context gcm;     gcm_init(&gcm, key);     unsigned char iv[12];     unsigned char tag[16];     get_secure_random(iv, 12);         for (int i = 0; i < ehdr->e_shnum; i++) {         if (shdr[i].sh_offset + shdr[i].sh_size > size) continue;         char *sname = shstrtab + shdr[i].sh_name;                 /* Selective encryption: only .rodata and .data */         if (strcmp(sname, ".rodata") == 0 || strcmp(sname, ".data") == 0) {             unsigned char *content = data + shdr[i].sh_offset;             unsigned char *ciphertext = (unsigned char *)malloc(shdr[i].sh_size);             if (ciphertext) {                 gcm_encrypt(&gcm, iv, 12, content, shdr[i].sh_size, ciphertext, tag);                 memcpy(content, ciphertext, shdr[i].sh_size);                 free(ciphertext);             }         }                 /* Mangle names but don't destroy headers yet to ensure it runs */         if (shdr[i].sh_type == SHT_SYMTAB || shdr[i].sh_type == SHT_STRTAB) {              /* In-place zeroing of symbol names to prevent simple strings analysis */              memset(data + shdr[i].sh_offset, 0, shdr[i].sh_size);         }                 /* Rename sections to random chars */         for (int j = 0; sname[j] != '\0'; j++) sname[j] = (char)('a' + (rand() % 26));     }         /* Only mangle entry for non-DYN files (executables) */     if (ehdr->e_type != ET_DYN) {         /* ehdr->e_entry ^= 0x... (Skipped for now to ensure it runs) */     } }

DECLARE_PROTECT_ELF_V4(32)
DECLARE_PROTECT_ELF_V4(64)

static int L_protect_binary(lua_State *L) {
    const char *input_path = luaL_checkstring(L, 1);
    const char *output_path = luaL_checkstring(L, 2);

    FILE *f = fopen(input_path, "rb");
    if (!f) return luaL_error(L, "cannot open input file");

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    if (fsize < 0) { fclose(f); return luaL_error(L, "ftell error"); }
    size_t size = (size_t)fsize;
    fseek(f, 0, SEEK_SET);

    unsigned char *data = (unsigned char *)malloc(size);
    if (!data) { fclose(f); return luaL_error(L, "out of memory"); }
    if (fread(data, 1, size, f) != size) { free(data); fclose(f); return luaL_error(L, "read error"); }
    fclose(f);

    if (size < 4 || memcmp(data, ELFMAG, SELFMAG) != 0) {
        free(data);
        return luaL_error(L, "not a valid ELF file");
    }

    unsigned char key[32];
    get_secure_random(key, 32);

    if (data[EI_CLASS] == ELFCLASS64) protect_elf64_v4(data, size, key);
    else if (data[EI_CLASS] == ELFCLASS32) protect_elf32_v4(data, size, key);

    FILE *out = fopen(output_path, "wb");
    if (!out) { free(data); return luaL_error(L, "cannot open output file"); }
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
