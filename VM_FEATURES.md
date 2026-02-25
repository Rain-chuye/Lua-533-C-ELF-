# 初叶定制商业级 Lua 5.3.3 虚拟机 & 二进制保护系统
# (Chuye Custom Commercial-Grade Lua 5.3.3 VM & Binary Protection System)

本项目提供了最高级别的原生二进制与逻辑保护，专为 Android 和 Linux 环境设计。

## 1. 原生二进制加固 (Advanced ELF Protector)
集成的 `vmp` 模块提供了超越普通加固工具的特性：
- **全架构支持**: 兼容 ELF32 和 ELF64 (ARM/x86)。
- **SHT 彻底破坏 (Section Header Table Corruption)**:
    - 保护后彻底抹除节区表 (`e_shoff = 0`)。
    - 使 `readelf`, `objdump` 无法工作，使 IDA Pro 等反汇编工具无法自动识别节区和符号。
    - 保持二进制文件可运行（通过 Program Headers 加载）。
- **XTEA 块加密**:
    - 使用 XTEA 算法代替简单的 XOR。
    - 对 `.rodata` 和 `.data` 段进行块加密。
    - 每个文件生成随机的 128 位加密密钥。
- **入口点混淆**: 使用非线性变换隐藏真实的程序入口。
- **符号表随机化**: 将所有剩余的符号名重命名为随机生成的无意义字符串。

## 2. 增强型反调试 (Advanced Anti-Debugging)
内置了多重防动态分析机制：
- **双进程自跟踪 (Fork-based Anti-Debug)**:
    - 启动时派生子进程对主进程进行 `PTRACE_ATTACH`。
    - 利用一个进程只能被一个 Tracer 跟踪的原理，彻底杜绝 GDB, IDA, Frida 的附着。
- **时间膨胀检测 (Timing Detection)**:
    - 关键逻辑段内置时间校对。
    - 检测由于单步调试或断点引起的毫秒级延迟，一旦发现即刻退出。
- **Proc 状态实时监控**: 持续轮询 `/proc/self/status` 中的 `TracerPid`。

## 3. 虚拟机指令级保护 (VM Instruction Protection)
- **动态指令加密**: 基于函数级随机种子的动态指令流解密。
- **操作码随机映射 (Opcode Randomization)**: 全局随机化的操作码表，彻底打破反向工具的通用性。
- **指令融合 (Instruction Fusion)**: 复杂逻辑合并为原子操作，提升性能的同时极大增加反编译难度。

## 4. 字符串与常量保护
- **全常量加密**: 整数、布尔、字符串在常量池中均以加密形式存在，运行时动态解密。

## 5. 调用方式 (How to use)
在 Lua 脚本中通过 `vmp` 模块一键保护：
```lua
local vmp = require "vmp"
vmp.protect("mylib.so", "mylib_vmp.so")
print("商业级加固已完成")
```

---
**初叶定制 - 致力于提供最坚固的安全防护解决方案。**
