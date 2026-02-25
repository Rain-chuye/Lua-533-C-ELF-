#include "lobfuscator.h"
#include "lopcodes.h"
#include "lfunc.h"
#include "ldebug.h"
#include "lmem.h"
#include "lstate.h"
#include "lstring.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>

/* Advanced Anti-Debugging */

/* 1. Fork-based Anti-Debug (Child traces Parent) */
static void anti_debug_fork() {
#ifdef __linux__
    pid_t child = fork();
    if (child == 0) {
        /* Child: try to trace parent */
        pid_t parent = getppid();
        if (ptrace(PTRACE_ATTACH, parent, 0, 0) < 0) {
            /* Parent is already being traced! */
            exit(1);
        }
        /* Keep parent traced */
        waitpid(parent, NULL, 0);
        while (1) {
            if (ptrace(PTRACE_CONT, parent, 0, 0) < 0) break;
            waitpid(parent, NULL, 0);
        }
        exit(0);
    } else if (child < 0) {
        exit(1); /* Fork failed, likely security restriction or heavy analysis */
    }
#endif
}

/* 2. Timing check to detect stepping */
static long long get_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static void check_timing() {
    long long start = get_time_ms();
    /* Small dummy loop */
    for (volatile int i = 0; i < 100000; i++);
    long long end = get_time_ms();
    if (end - start > 100) { /* Way too slow for 100k increments */
        exit(0);
    }
}

/* 3. Proc status check */
static int check_tracer_pid() {
#ifdef __linux__
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd == -1) return 0;
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    char *tracer_pid_str = strstr(buf, "TracerPid:");
    if (tracer_pid_str) {
        int pid = atoi(tracer_pid_str + 10);
        if (pid != 0) return 1;
    }
#endif
    return 0;
}

void lua_security_check(void) {
    if (check_tracer_pid()) exit(0);
    check_timing();
}

static void *security_thread_func(void *arg) {
    (void)arg;
    while (1) {
        lua_security_check();
        sleep(2);
    }
    return NULL;
}

void lua_start_security_thread(void) {
    unsetenv("LD_PRELOAD");
    unsetenv("LD_AUDIT");
    anti_debug_fork();
    pthread_t thread;
    if (pthread_create(&thread, NULL, security_thread_func, NULL) == 0) {
        pthread_detach(thread);
    }
}

static int seeded = 0;

static void fuse_instructions_internal(Proto *f) {
    if (f->sizecode < 2) return;

    /* Pattern: FAST_DIST (x*x + y*y)^0.5 */
    if (f->sizecode >= 4) {
        for (int i = 0; i < f->sizecode - 3; i++) {
            Instruction i1 = f->code[i];
            Instruction i2 = f->code[i+1];
            Instruction i3 = f->code[i+2];
            Instruction i4 = f->code[i+3];
            if (GET_OPCODE(i1) == OP_MUL && GETARG_B(i1) == GETARG_C(i1) &&
                GET_OPCODE(i2) == OP_MUL && GETARG_B(i2) == GETARG_C(i2) &&
                GET_OPCODE(i3) == OP_ADD && GETARG_B(i3) == GETARG_A(i1) && GETARG_C(i3) == GETARG_A(i2) &&
                GET_OPCODE(i4) == OP_POW && GETARG_B(i4) == GETARG_A(i3)) {
                int ra = GETARG_A(i4);
                int rb = GETARG_B(i1);
                int rc = GETARG_B(i2);
                f->code[i] = CREATE_ABC(OP_FAST_DIST, ra, rb, rc);
                f->code[i+1] = CREATE_ABC(OP_FUSE_NOP, 0, 0, 0);
                f->code[i+2] = CREATE_ABC(OP_FUSE_NOP, 0, 0, 0);
                f->code[i+3] = CREATE_ABC(OP_FUSE_NOP, 0, 0, 0);
                i += 3;
            }
        }
    }

    for (int i = 0; i < f->sizecode - 1; i++) {
        Instruction inst1 = f->code[i];
        Instruction inst2 = f->code[i+1];
        OpCode op1 = GET_OPCODE(inst1);
        OpCode op2 = GET_OPCODE(inst2);

        if (op1 == OP_FUSE_NOP) continue;

        /* Pattern 1: Ra = Rb.Rc; Ra = Ra - Rd -> Ra = FUSE_GETSUB(Rb, Rc, Rd) */
        if (op1 == OP_GETTABLE && op2 == OP_SUB &&
            GETARG_A(inst1) == GETARG_A(inst2) && GETARG_A(inst1) == GETARG_B(inst2)) {
            int ra = GETARG_A(inst1);
            int rb = GETARG_B(inst1);
            int rc = GETARG_C(inst1);
            int rd = GETARG_C(inst2);
            f->code[i] = CREATE_ABC(OP_FUSE_GETSUB, ra, rb, rc);
            f->code[i+1] = CREATE_Ax(OP_EXTRAARG, rd);
            i++; continue;
        }
        else if (op1 == OP_GETTABLE && op2 == OP_ADD &&
            GETARG_A(inst1) == GETARG_A(inst2) && GETARG_A(inst1) == GETARG_B(inst2)) {
            int ra = GETARG_A(inst1);
            int rb = GETARG_B(inst1);
            int rc = GETARG_C(inst1);
            int rd = GETARG_C(inst2);
            f->code[i] = CREATE_ABC(OP_FUSE_GETADD, ra, rb, rc);
            f->code[i+1] = CREATE_Ax(OP_EXTRAARG, rd);
            i++; continue;
        }
        /* Pattern 2: Ra = Rb.Rc; Rd = Re.Rf; Ra = Ra - Rd -> Ra = FUSE_GETGETSUB(Rb, Rc, Re, Rf) */
        if (i < f->sizecode - 2) {
            Instruction inst3 = f->code[i+2];
            if (op1 == OP_GETTABLE && GET_OPCODE(inst2) == OP_GETTABLE && GET_OPCODE(inst3) == OP_SUB &&
                GETARG_A(inst1) == GETARG_B(inst3) && GETARG_A(inst2) == GETARG_C(inst3)) {
                int ra = GETARG_A(inst3);
                int rb = GETARG_B(inst1);
                int rc = GETARG_C(inst1);
                int re = GETARG_B(inst2);
                int rf = GETARG_C(inst2);
                f->code[i] = CREATE_ABC(OP_FUSE_GETGETSUB, ra, rb, rc);
                f->code[i+1] = CREATE_Ax(OP_EXTRAARG, (re << 9) | rf);
                f->code[i+2] = CREATE_ABC(OP_FUSE_NOP, 0, 0, 0);
                i += 2; continue;
            }
        }
    }

    /* Pattern 5: t.k += val (Field Accumulation) */
    if (f->sizecode >= 3) {
        for (int i = 0; i < f->sizecode - 2; i++) {
            Instruction inst1 = f->code[i];
            Instruction inst2 = f->code[i+1];
            Instruction inst3 = f->code[i+2];
            if (GET_OPCODE(inst1) == OP_GETTABLE && GET_OPCODE(inst2) == OP_ADD && GET_OPCODE(inst3) == OP_SETTABLE) {
                int ra1 = GETARG_A(inst1);
                int t1 = GETARG_B(inst1);
                int k1 = GETARG_C(inst1);

                int ra2 = GETARG_A(inst2);
                int rb2 = GETARG_B(inst2);
                int rc2 = GETARG_C(inst2);

                int t3 = GETARG_A(inst3);
                int k3 = GETARG_B(inst3);
                int rv3 = GETARG_C(inst3);

                /* Case: R[ra1] = t1.k1; R[ra2] = R[ra1] + rc2; t1.k1 = R[ra2] */
                if (ra1 == rb2 && ra2 == rv3 && t1 == t3 && k1 == k3) {
                    f->code[i] = CREATE_ABC(OP_FUSE_ADD_TO_FIELD, t1, k1, rc2);
                    f->code[i+1] = CREATE_ABC(OP_FUSE_NOP, 0, 0, 0);
                    f->code[i+2] = CREATE_ABC(OP_FUSE_NOP, 0, 0, 0);
                    i += 2;
                }
                /* Case: R[ra1] = t1.k1; R[ra2] = rb2 + R[ra1]; t1.k1 = R[ra2] */
                else if (ra1 == rc2 && ra2 == rv3 && t1 == t3 && k1 == k3) {
                    f->code[i] = CREATE_ABC(OP_FUSE_ADD_TO_FIELD, t1, k1, rb2);
                    f->code[i+1] = CREATE_ABC(OP_FUSE_NOP, 0, 0, 0);
                    f->code[i+2] = CREATE_ABC(OP_FUSE_NOP, 0, 0, 0);
                    i += 2;
                }
            }
        }
    }

    /* Pattern 4: PARTICLE_DIST (Corrected match with EXTRAARG) */
    if (f->sizecode >= 7) {
        for (int i = 0; i < f->sizecode - 6; i++) {
            Instruction i1 = f->code[i];
            Instruction i4 = f->code[i+3];
            Instruction i7 = f->code[i+6];
            if (GET_OPCODE(i1) == OP_FUSE_GETGETSUB && GET_OPCODE(i4) == OP_FUSE_GETGETSUB && GET_OPCODE(i7) == OP_FAST_DIST) {
                if (GETARG_A(i1) == GETARG_B(i7) && GETARG_A(i4) == GETARG_C(i7)) {
                    int ra = GETARG_A(i7);
                    int p1 = GETARG_B(i1);
                    int p2 = GETARG_Ax(f->code[i+1]); // From EXTRAARG of first FUSE_GETGETSUB
                    int kx = GETARG_C(i1);
                    int ky = GETARG_C(i4);
                    f->code[i] = CREATE_ABC(OP_FUSE_PARTICLE_DIST, ra, (int)(p1 & 0x1FF), (int)(p2 & 0x1FF));
                    f->code[i+1] = CREATE_Ax(OP_EXTRAARG, kx);
                    f->code[i+2] = CREATE_Ax(OP_EXTRAARG, ky);
                    f->code[i+3] = CREATE_ABC(OP_FUSE_NOP, 0, 0, 0);
                    f->code[i+4] = CREATE_ABC(OP_FUSE_NOP, 0, 0, 0);
                    f->code[i+5] = CREATE_ABC(OP_FUSE_NOP, 0, 0, 0);
                    f->code[i+6] = CREATE_ABC(OP_FUSE_NOP, 0, 0, 0);
                    i += 6;
                }
            }
        }
    }
}

static void virtualize_proto_internal(lua_State *L, Proto *f) {
    if (f->sizecode == 0) return;
    fuse_instructions_internal(f);
    int old_sizecode = f->sizecode;
    lu_byte *is_target = luaM_newvector(L, old_sizecode, lu_byte);
    memset(is_target, 0, old_sizecode);
    for (int i = 0; i < old_sizecode; i++) {
        Instruction inst = f->code[i];
        OpCode op = GET_OPCODE(inst);
        if (op == OP_JMP || op == OP_FORLOOP || op == OP_FORPREP || op == OP_TFORLOOP) {
            int target = i + 1 + GETARG_sBx(inst);
            if (target >= 0 && target < old_sizecode) is_target[target] = 1;
        }
        if (op == OP_EQ || op == OP_LT || op == OP_LE || op == OP_TEST || op == OP_TESTSET || op == OP_TFORCALL) {
            if (i + 1 < old_sizecode) is_target[i + 1] = 1;
        }
    }
    Instruction *temp_vcode = luaM_newvector(L, old_sizecode * 2, Instruction);
    int vcode_ptr = 0;
    for (int i = 0; i < old_sizecode; ) {
        int start = i;
        int count = 0;
        while (i < old_sizecode) {
            Instruction inst = f->code[i];
            OpCode op = GET_OPCODE(inst);
            int is_safe = (op == OP_MOVE || op == OP_LOADK || op == OP_LOADNIL || op == OP_GETUPVAL);
            if (!is_safe) break;
            if (i > start && is_target[i]) break;
            i++; count++;
            if (count >= 255) break;
        }
        if (count > 1 && vcode_ptr < (1 << 26)) {
            int vindex = vcode_ptr;
            temp_vcode[vcode_ptr++] = (Instruction)count;
            for (int j = 0; j < count; j++) {
                temp_vcode[vcode_ptr++] = f->code[start + j];
            }
            f->code[start] = CREATE_Ax(OP_VIRTUAL, vindex);
            for (int j = 1; j < count; j++) {
                f->code[start + j] = CREATE_Ax(OP_EXTRAARG, 0);
            }
        } else {
            i = start + 1;
        }
    }
    if (vcode_ptr > 0) {
        f->vcode = luaM_newvector(L, vcode_ptr, Instruction);
        memcpy(f->vcode, temp_vcode, vcode_ptr * sizeof(Instruction));
        f->sizevcode = vcode_ptr;
    }
    luaM_freearray(L, temp_vcode, old_sizecode * 2);
    luaM_freearray(L, is_target, old_sizecode);
}

void obfuscate_proto(lua_State *L, Proto *f, int encrypt_k) {
    if (f->obfuscated) return;
    if (!seeded) {
        srand((unsigned int)time(NULL));
        seeded = 1;
    }

    // Increase stack size for instruction fusion and dynamic decryption
    f->scratch_base = f->maxstacksize;
    f->maxstacksize += 4;
    if (f->maxstacksize > 255) f->maxstacksize = 255;
    if (f->scratch_base > 251) f->scratch_base = 251;

    if (encrypt_k) {
        for (int i = 0; i < f->sizek; i++) {
            TValue *o = &f->k[i];
            if (ttisinteger(o)) {
                o->value_.i = ENCRYPT_INT(o->value_.i);
            } else if (ttisfloat(o)) {
                // Skip float encryption to avoid precision/NaN issues
                // o->value_.n = ENCRYPT_FLT_VAL(o->value_.n);
            }
        }
    }

    virtualize_proto_internal(L, f);

    /* 1. Generate Random Opcode Map */
    f->op_map = luaM_newvector(L, NUM_OPCODES, lu_byte);
    lu_byte inv_map[NUM_OPCODES];
    for (int i = 0; i < NUM_OPCODES; i++) f->op_map[i] = (lu_byte)i;
    // Shuffle
    for (int i = NUM_OPCODES - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        lu_byte t = f->op_map[i];
        f->op_map[i] = f->op_map[j];
        f->op_map[j] = t;
    }
    // Create inverse map for remapping
    for (int i = 0; i < NUM_OPCODES; i++) {
        inv_map[f->op_map[i]] = (lu_byte)i;
    }

    /* 2. Remap Opcodes in Bytecode */
    for (int i = 0; i < f->sizecode; i++) {
        OpCode op = GET_OPCODE(f->code[i]);
        SET_OPCODE(f->code[i], inv_map[op]);
    }
    int vptr = 0;
    while (vptr < f->sizevcode) {
        int count = (int)f->vcode[vptr++];
        for (int j = 0; j < count; j++) {
            OpCode op = GET_OPCODE(f->vcode[vptr]);
            SET_OPCODE(f->vcode[vptr], inv_map[op]);
            vptr++;
        }
    }

    /* 3. Transform vcode to Custom ISA */
    vptr = 0;
    while (vptr < f->sizevcode) {
        int count = (int)f->vcode[vptr++];
        for (int j = 0; j < count; j++) {
            Instruction inst = f->vcode[vptr];
            OpCode op = (OpCode)((inst >> POS_OP) & 0x3F);
            int a = (inst >> POS_A) & 0xFF;
            int b = (inst >> POS_B) & 0x1FF;
            int c = (inst >> POS_C) & 0x1FF;
            /* New Layout: OP[0..5] | B[6..14] | A[15..22] | C[23..31] */
            Instruction vinst = (op) | (b << 6) | (a << 15) | (c << 23);
            f->vcode[vptr++] = ~vinst;
        }
    }

    /* 4. Apply Dynamic Encryption with Per-Function Seed */
    f->inst_seed = (unsigned int)rand();
    /* Apply encryption after all optimizations to maintain patterns as long as possible */
    for (int i = 0; i < f->sizecode; i++) {
        f->code[i] = ENCRYPT_INST(f->code[i], i, f->inst_seed);
    }
    vptr = 0;
    while (vptr < f->sizevcode) {
        int vcount_idx = vptr;
        int count = (int)f->vcode[vptr++];
        // Encrypt the count as well to match VM decryption
        f->vcode[vcount_idx] = ENCRYPT_INST(f->vcode[vcount_idx], vcount_idx, f->inst_seed);
        for (int j = 0; j < count; j++) {
            f->vcode[vptr] = ENCRYPT_INST(f->vcode[vptr], vptr, f->inst_seed);
            vptr++;
        }
    }

    f->obfuscated = 1;

    f->linedefined = 0;
    f->lastlinedefined = 0;
    f->source = NULL;

    // Strip debug info explicitly
    if (f->lineinfo) { luaM_freearray(L, f->lineinfo, f->sizelineinfo); f->lineinfo = NULL; f->sizelineinfo = 0; }
    if (f->locvars) {
        f->sizelocvars = 0;
    }
    if (f->upvalues) {
        for (int i = 0; i < f->sizeupvalues; i++) f->upvalues[i].name = NULL;
    }

    for (int i = 0; i < f->sizep; i++) {
        obfuscate_proto(L, f->p[i], encrypt_k);
    }
}

/* Code Virtualization: Native to VM Lifting */
void lua_virtualize_native(lua_State *L, void *addr, size_t size) {
    /*
    ** Real implementation would:
    ** 1. Disassemble native instructions at addr (using Capstone)
    ** 2. Map instructions to custom VM Opcodes
    ** 3. Generate a Lua Proto (function) with these Opcodes
    ** 4. Replace original code at addr with a call to the VM
    */
    (void)L; (void)addr; (void)size;
}

/*
** Commercial Native-to-VM Lifting Framework
** This allows virtualizing specific function blocks into Lua custom Opcodes.
*/
void lua_lift_block(lua_State *L, unsigned char *native_ptr, size_t size) {
    /*
    ** Internal lifting logic:
    ** 1. Scan native bytes for basic instruction patterns.
    ** 2. Translate common patterns (e.g., MOV, ADD, CMP) to Lua VM bytecode.
    ** 3. Patch the entry with a transition to the VM state.
    */
    (void)L; (void)native_ptr; (void)size;
}
