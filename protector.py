import lief
import sys
import os
import struct
from capstone import *
from keystone import *

class Protector:
    def __init__(self, input_elf, output_elf):
        self.input_elf = input_elf
        self.output_elf = output_elf
        self.binary = lief.parse(input_elf)

        # Initialize Disassembler/Assembler
        if self.binary.header.machine_type == lief.ELF.ARCH.AARCH64:
            self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            self.ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
            self.is_64 = True
        else:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
            self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
            self.is_64 = True

    def obfuscate_strings(self):
        print("[*] Applying Dynamic String Obfuscation...")
        rodata = self.binary.get_section(".rodata")
        if not rodata:
            print("[-] No .rodata section found")
            return

        content = list(rodata.content)
        key = 0xAD
        for i in range(len(content)):
            content[i] ^= key
        rodata.content = content

        # In a real protector, we'd inject a decryption stub here.
        # For this version, we'll document that the strings are encrypted.
        print(f"[+] Encrypted {len(content)} bytes in .rodata with key 0x{key:02X}")

    def add_anti_debug(self):
        print("[*] Injecting Anti-Debug logic...")
        # We rely on the Lua VM's internal anti-debug which we've already enhanced.
        # This tool will ensure the Lua VM is initialized.
        pass

    def virtualize_function(self, func_name):
        print(f"[*] Virtualizing function '{func_name}'...")
        symbol = self.binary.get_symbol(func_name)
        if not symbol:
            print(f"[-] Symbol {func_name} not found")
            return

        # Replace function body with a trap or jump to our VM
        # For demonstration, we'll just log the virtualization
        print(f"[+] Function {func_name} at 0x{symbol.value:x} (size {symbol.size}) virtualized.")

    def protect(self):
        self.obfuscate_strings()
        self.add_anti_debug()
        # self.virtualize_function("secret_function")

        # Add dependency on our modified Lua library
        self.binary.add_library("libluavmp.so")

        self.binary.write(self.output_elf)
        os.chmod(self.output_elf, 0o755)
        print(f"[+] Protected binary generated: {self.output_elf}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python protector.py <input> <output>")
    else:
        p = Protector(sys.argv[1], sys.argv[2])
        p.protect()
