#ifndef vmp_runtime_h
#define vmp_runtime_h

#include <stddef.h>

/*
** 商业级解密接口 (Commercial Decryption Interface)
** 调用此函数来动态解密受保护的 .so 内存段
*/
void vmp_decrypt_so(void *base_addr, const unsigned char *key);

#endif
