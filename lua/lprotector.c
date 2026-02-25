#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
#include "lua.h"
#include "lauxlib.h"
#include "lprotector.h"

#define PROTECT_KEY 0x8F

/* Support for both 32 and 64 bit */
#define DECLARE_PROTECT_ELF(bits) static void protect_elf##bits(unsigned char *data, size_t size) {     Elf##bits##_Ehdr *ehdr = (Elf##bits##_Ehdr *)data;     Elf##bits##_Shdr *shdr = (Elf##bits##_Shdr *)(data + ehdr->e_shoff);     char *shstrtab = (char *)(data + shdr[ehdr->e_shstrndx].sh_offset);     for (int i = 0; i < ehdr->e_shnum; i++) {         char *sname = shstrtab + shdr[i].sh_name;         if (strcmp(sname, ".rodata") == 0 || strcmp(sname, ".data") == 0) {             unsigned char *content = data + shdr[i].sh_offset;             for (size_t j = 0; j < shdr[i].sh_size; j++) {                 content[j] ^= PROTECT_KEY;             }         }         if (strcmp(sname, ".comment") == 0) {             memcpy(sname, ".chuye", 7);         }         if (strcmp(sname, ".symtab") == 0) {             memcpy(sname, ".vmp_sym", 8);         }     }     /* Obfuscate Entry Point if it is an executable */     if (ehdr->e_type == ET_EXEC) {         ehdr->e_entry ^= 0xDEADBEEF;     } }

DECLARE_PROTECT_ELF(32)
DECLARE_PROTECT_ELF(64)

static int L_protect_binary(lua_State *L) {
    const char *input_path = luaL_checkstring(L, 1);
    const char *output_path = luaL_checkstring(L, 2);

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
        protect_elf64(data, size);
    } else if (data[EI_CLASS] == ELFCLASS32) {
        protect_elf32(data, size);
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
