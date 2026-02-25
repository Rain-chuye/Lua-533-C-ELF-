#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include "lua.h"
#include "lauxlib.h"
#include "lprotector.h"

/* XTEA Encryption Implementation */
static void xtea_encrypt(uint32_t num_rounds, uint32_t v[2], uint32_t const k[4]) {
    uint32_t i;
    uint32_t v0 = v[0], v1 = v[1], sum = 0, delta = 0x9E3779B9;
    for (i = 0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
    }
    v[0] = v0; v[1] = v1;
}

static void encrypt_buffer(unsigned char *data, size_t size, uint32_t key[4]) {
    size_t i;
    for (i = 0; i + 8 <= size; i += 8) {
        xtea_encrypt(32, (uint32_t *)(data + i), key);
    }
    for (; i < size; i++) {
        data[i] ^= (unsigned char)(key[i % 4]);
    }
}

static uint64_t mangle_entry(uint64_t entry, uint32_t key) {
    entry ^= (uint64_t)key << 32 | key;
    entry = (entry << 13) | (entry >> (64 - 13));
    entry += 0xABCDEFFF12345678ULL;
    return entry;
}

#define DECLARE_PROTECT_ELF_ADVANCED(bits) static void protect_elf##bits##_hardened(unsigned char *data, size_t size, uint32_t key[4]) {     Elf##bits##_Ehdr *ehdr = (Elf##bits##_Ehdr *)data;     if (ehdr->e_shoff == 0) return;     Elf##bits##_Shdr *shdr = (Elf##bits##_Shdr *)(data + ehdr->e_shoff);     char *shstrtab = (char *)(data + shdr[ehdr->e_shstrndx].sh_offset);         for (int i = 0; i < ehdr->e_shnum; i++) {         char *sname = shstrtab + shdr[i].sh_name;         /* Encrypt sections and corrupt symbols */         if (strcmp(sname, ".rodata") == 0 || strcmp(sname, ".data") == 0) {             encrypt_buffer(data + shdr[i].sh_offset, shdr[i].sh_size, key);         }         if (strcmp(sname, ".symtab") == 0 || strcmp(sname, ".strtab") == 0) {             memset(data + shdr[i].sh_offset, 0, shdr[i].sh_size);         }         /* Randomize names */         for (size_t j = 0; sname[j] != '\0'; j++) sname[j] = (char)(rand() % 26 + 'a');     }         ehdr->e_entry = (Elf##bits##_Addr)mangle_entry((uint64_t)ehdr->e_entry, key[0]);         /* Wipe SHT Metadata */     ehdr->e_shoff = 0;     ehdr->e_shnum = 0;     ehdr->e_shstrndx = 0; }

DECLARE_PROTECT_ELF_ADVANCED(32)
DECLARE_PROTECT_ELF_ADVANCED(64)

static int L_protect_binary(lua_State *L) {
    const char *input_path = luaL_checkstring(L, 1);
    const char *output_path = luaL_checkstring(L, 2);

    uint32_t key[4];
    srand((unsigned int)time(NULL));
    for(int i=0; i<4; i++) key[i] = (uint32_t)rand();

    FILE *f = fopen(input_path, "rb");
    if (!f) return luaL_error(L, "cannot open input file: %s", input_path);

    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *data = (unsigned char *)malloc(size);
    if (!data) { fclose(f); return luaL_error(L, "out of memory"); }
    if (fread(data, 1, size, f) != size) { free(data); fclose(f); return luaL_error(L, "read error"); }
    fclose(f);

    if (size < 4 || memcmp(data, ELFMAG, SELFMAG) != 0) {
        free(data);
        return luaL_error(L, "not a valid ELF file");
    }

    if (data[EI_CLASS] == ELFCLASS64) {
        protect_elf64_hardened(data, size, key);
    } else if (data[EI_CLASS] == ELFCLASS32) {
        protect_elf32_hardened(data, size, key);
    }

    FILE *out = fopen(output_path, "wb");
    if (!out) { free(data); return luaL_error(L, "cannot open output file for writing: %s", output_path); }
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
