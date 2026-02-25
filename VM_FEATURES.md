# 魔改版 Lua 5.3.3 虚拟机功能说明 (Magic Lua 5.3.3 VM Features)

本项目基于 Lua 5.3.3 进行了深度定制，旨在提供商业级的安全保护和性能优化。以下是该魔改版虚拟机的核心功能列表：

## 1. 指令混淆与加密 (Instruction Obfuscation & Encryption)
- **动态指令加密**: 每一层函数原型（Proto）都拥有独立的随机种子 (`inst_seed`)。指令在加载后会被动态解密，防止静态分析。
- **操作码随机化 (Opcode Shuffling)**: VM 使用自定义的操作码映射表 (`op_map`)。原始的 Lua Opcode 被打乱并映射到新的位置，即使是标准的 Lua 反编译器也无法直接处理。
- **自定义指令格式**: 在 `OP_VIRTUAL` 模式下，指令位域被重新排列（例如：OP|B|A|C 布局），并结合了按位取反等变换。

## 2. 虚拟机指令融合 (Instruction Fusion / Macros)
为了提高执行效率并增加分析难度，VM 引入了多个复合指令，将常见的指令组合合并为单个高效操作：
- **`OP_FUSE_GETGETSUB`**: 合并两次表查找与一次减法操作。
- **`OP_FUSE_PARTICLE_DIST`**: 针对特定算法（如距离计算）的专用优化指令。
- **`OP_FUSE_ADD_TO_FIELD`**: 优化 `t.k = t.k + v` 模式的操作。
- **`OP_FAST_DIST`**: 硬件加速级的距离运算指令。

## 3. 常量池保护 (Constant Obfuscation)
- **数值加密**: 所有的整数常量在存储时都经过了异或（XOR）、加法（ADD）和乘法（MUL）的多重变换。在运行时，VM 会在访问常量时自动解密。
- **字符串混淆**: 支持对常量池中的字符串进行预处理和隐藏。

## 4. 脚本级安全封装 (Script-level Protection)
- **初叶定制加密 (`luaL_encrypt_chuye_script`)**:
    - 结合了数据压缩与分段加密技术。
    - 生成一个合法的 Lua 加载脚本，通过全局 `LuaVMP` 占位符在运行时解密并加载字节码。
    - 包含 CRC32 校验，确保脚本完整性。

## 5. 虚拟机内核增强 (VM Core Enhancements)
- **自定义签名**: 将标准的 Lua 签名 `\x1bLua` 修改为 `\x1bLUAX`，防止标准工具识别。
- **SHA256 内置支持**: 集成了原生的 SHA256 算法，用于数据校验和安全通信。
- **反调试预留**: 内置 `lua_security_check` 和 `lua_start_security_thread` 接口，可扩展商业级的反调试和进程监控功能。
- **寄存器优化**: 扩展了 `scratch_base` 等字段，为复杂的融合指令提供额外的草稿寄存器空间。

## 6. 调试信息剥离 (Debug Stripping)
- 强制剥离函数名、行号 (`lineinfo`)、局部变量名 (`locvars`) 等调试信息，最大程度保护源代码逻辑。

---
**注意**: 该 VM 配合专属的 `.so/ELF` 保护工具使用时，可提供最高级别的二进制与逻辑双重防护。
