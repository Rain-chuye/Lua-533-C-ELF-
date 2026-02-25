# 使用说明 (Usage Guide)

本项目提供了一套完整的二进制保护方案，结合了魔改版 Lua VM 和原生 ELF/SO 保护工具。

## 1. 编译环境
- 操作系统: Linux / Android (NDK)
- 依赖库: `LIEF`, `Capstone`, `Keystone` (Python 依赖)
- 编译器: `gcc` 或 `clang`

## 2. 保护二进制文件
使用 `protector.py` 对编译好的 `.so` 或 ELF 可执行文件进行保护：

```bash
python protector.py <输入文件> <输出文件>
```

保护功能包括：
- **动态字符串加密**: 自动加密 `.rodata` 段，防止静态分析。
- **反调试注入**: 联动 Lua VM 的原生反调试机制（ptrace, TracerPid, Frida 检测）。
- **VMP 虚拟化**: 支持将关键函数逻辑转向 Lua VM 执行（需配合 symbol 配置）。
- **依赖注入**: 自动为目标添加 `libluavmp.so` 依赖。

## 3. 在 Lua 中调用
魔改 VM 提供了增强的调用方式。对于加密后的脚本或保护后的逻辑，可以使用以下方式：

### C API 调用示例:
```c
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

int main() {
    lua_State *L = luaL_newstate();
    luaL_openlibs(L);

    // 启动安全监控线程（反调试）
    lua_start_security_thread();

    // 加载受保护的 Lua 逻辑
    if (luaL_loadfile(L, "protected_script.luac") == LUA_OK) {
        lua_pcall(L, 0, 0, 0);
    }

    lua_close(L);
    return 0;
}
```

## 4. 运行受保护的程序
由于受保护的程序依赖于 `libluavmp.so`，请确保该库在系统的加载路径中：

```bash
export LD_LIBRARY_PATH=./lua:
./sample_elf_protected
```

---
**商业保护建议**: 为了达到最高安全级别，建议在源码中使用宏标记关键函数，并配合 `protector.py` 的虚拟化功能使用。
