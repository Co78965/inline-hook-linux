#include "HookPatch.hpp"

#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <cerrno>
#include <Zydis/Zydis.h>
#include <map>

const size_t HookPatch::JUMP_SIZE = 14;

thread_local HookPatch* g_currentHook = nullptr;

std::map<unsigned int, PatchInfo> patchedFunctions;

HookController* HookController::hookController = nullptr;

HookController* HookController::GetHookController() {
    if (!hookController) {
        hookController = new HookController(nullptr);
    }
    return hookController;
}

HookPatch* HookController::GetHookPatch() {
    return hookPatch;
}

void HookPatch::defaultLogger(const std::string funcName) {
    std::cerr << "[HOOK] " << funcName << "\n";
}

extern "C" uint64_t loggingWrapper_c(unsigned int id) {
    std::cout << id << std::endl;
    auto info = patchedFunctions[id];

    try {
        HookPatch::defaultLogger(std::string(info.functionName));
    } catch (...) {
    }

    void* tramp = info.trampoline.code;
    return reinterpret_cast<uint64_t>(tramp);
}

extern "C" void asm_wrapper() {
    asm volatile(
        ".intel_syntax noprefix\n"
        "sub rsp, 56\n"

        "mov QWORD PTR [rsp + 0], rdi\n"
        "mov QWORD PTR [rsp + 8], rsi\n"
        "mov QWORD PTR [rsp + 16], rdx\n"
        "mov QWORD PTR [rsp + 24], rcx\n"
        "mov QWORD PTR [rsp + 32], r8\n"
        "mov QWORD PTR [rsp + 40], r9\n"

        "mov rdi, r10\n"

        "call loggingWrapper_c\n"

        "mov rdi, QWORD PTR [rsp + 0]\n"
        "mov rsi, QWORD PTR [rsp + 8]\n"
        "mov rdx, QWORD PTR [rsp + 16]\n"
        "mov rcx, QWORD PTR [rsp + 24]\n"
        "mov r8,  QWORD PTR [rsp + 32]\n"
        "mov r9,  QWORD PTR [rsp + 40]\n"

        "add rsp, 56\n"

        "jmp rax\n"
        ".att_syntax\n"
    );
}

HookPatch::HookPatch(LogCallback callback){
    if (callback) logCallback_ = callback;
    else logCallback_ = &HookPatch::defaultLogger;
}

HookPatch::~HookPatch() {
    remove();
}

bool HookPatch::install(std::string functionName) {
    functionName_ = functionName;
    void* target = dlsym(RTLD_DEFAULT, functionName.c_str());
    if (!target) {
        std::cerr << "dlsym failed for " << functionName << ": " << dlerror() << "\n";
        return false;
    }
    originalFunction_ = target;

    if (!createTrampoline(target)) {
        std::cerr << "createTrampoline failed\n";
        return false;
    }
    uint8_t origFirst[16];
    memcpy(origFirst, target, 16);
    if (!patchFunction(target)) {
        std::cerr << "patchFunction failed\n";
        return false;
    }
    
    PatchInfo info;
    info.originalAddress = target;
    info.trampoline = trampoline_;
    strcpy(info.functionName, functionName.c_str());

    // сохранить stub из lastStub
    info.stub = lastStub;
    info.stubSize = lastStubSize;
    printf("stub at %p, target at %p\n", lastStub, originalFunction_);

    patchedFunctions[nextId] = info;
    installedId = nextId; // сохраняем id в объекте
    nextId++;
    
    installed_ = true;
    //std::cout << "Patch success! patchedFunctions.size >> " << patchedFunctions.size() << std::endl;
    return true;
}

bool HookPatch::remove() {
    if (!installed_) return true;
    restoreFunction();
    if (trampoline_.code) {
        munmap(trampoline_.code, trampoline_.size);
        trampoline_.code = nullptr;
    }
    installed_ = false;
    return true;
}

static inline size_t emit_abs_call(uint8_t* dst, uint64_t target){
    // mov rax, imm64
    dst[0] = 0x48;
    dst[1] = 0xB8;
    *reinterpret_cast<uint64_t*>(&dst[2]) = target;
    // call rax
    dst[10] = 0xFF;
    dst[11] = 0xD0;
    dst[12] = 0x01;
    return 12;
}

bool HookPatch::createTrampoline(void* targetFunction) {
    uint8_t* src_base = reinterpret_cast<uint8_t*>(targetFunction);

    const size_t maxTramp = 1024;
    void* mem = mmap(nullptr, maxTramp, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        std::cerr << "mmap failed: " << strerror(errno) << "\n";
        return false;
    }
    uint8_t* tramp = static_cast<uint8_t*>(mem);
    size_t tramp_off = 0;

    ZydisDecoder decoder;
    if (ZYAN_STATUS_SUCCESS != ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)) {
        std::cerr << "ZydisDecoderInit failed\n";
        munmap(tramp, maxTramp);
        return false;
    }

    size_t prefix_skip = 0;
    if (src_base[0] == 0xF3 && src_base[1] == 0x0F && src_base[2] == 0x1E && src_base[3] == 0xFA) {
        tramp[tramp_off++] = src_base[0];
        tramp[tramp_off++] = src_base[1];
        tramp[tramp_off++] = src_base[2];
        tramp[tramp_off++] = src_base[3];
        prefix_skip = 4;
    }

    size_t copied = 0;

    while (copied < JUMP_SIZE) {
        ZydisDecodedInstruction instr;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

        ZyanStatus st = ZydisDecoderDecodeFull(
            &decoder,
            src_base + prefix_skip + copied,
            64,
            &instr,
            operands);

        if (st != ZYAN_STATUS_SUCCESS) {
            std::cerr << "Zydis failed to decode at " << static_cast<void*>(src_base + prefix_skip + copied) << "\n";
            munmap(tramp, maxTramp);
            return false;
        }

        uint8_t ilen = instr.length;
        if (ilen == 0) {
            std::cerr << "Zydis returned zero-length instruction\n";
            munmap(tramp, maxTramp);
            return false;
        }

        for (uint8_t opIndex = 0; opIndex < instr.operand_count; ++opIndex) {
            const ZydisDecodedOperand& op = operands[opIndex];
            if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                if (op.mem.base == ZYDIS_REGISTER_RIP) {
                    std::cerr << "createTrampoline: found RIP-relative memory operand at "
                              << static_cast<void*>(src_base + prefix_skip + copied)
                              << " — refusing to patch (safe fallback). Use relocation if needed.\n";
                    munmap(tramp, maxTramp);
                    return false;
                }
            }
        }

        bool replacedRel = false;
        if (instr.mnemonic == ZYDIS_MNEMONIC_CALL || instr.mnemonic == ZYDIS_MNEMONIC_JMP) {
            for (uint8_t k = 0; k < instr.operand_count; ++k) {
                const ZydisDecodedOperand& op = operands[k];
                if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_signed) {
                    int64_t rel = op.imm.value.s;
                    uint64_t instr_addr = reinterpret_cast<uint64_t>(src_base) + prefix_skip + copied;
                    uint64_t abs_target = instr_addr + ilen + rel;

                    if (tramp_off + 12 + 32 >= maxTramp) {
                        std::cerr << "trampoline buffer too small for abs-call\n";
                        munmap(tramp, maxTramp);
                        return false;
                    }
                    emit_abs_call(tramp + tramp_off, abs_target);
                    tramp_off += 12;
                    copied += ilen;
                    replacedRel = true;
                    break;
                }
            }
        }

        if (replacedRel) {
            continue;
        }

        if (tramp_off + ilen + 32 >= maxTramp) {
            std::cerr << "trampoline buffer too small\n";
            munmap(tramp, maxTramp);
            return false;
        }
        memcpy(tramp + tramp_off, src_base + prefix_skip + copied, ilen);
        tramp_off += ilen;
        copied += ilen;
    }

    if (tramp_off + 14 >= maxTramp) {
        std::cerr << "trampoline buffer too small for final jmp\n";
        munmap(tramp, maxTramp);
        return false;
    }
    uint8_t* pos = tramp + tramp_off;
    pos[0] = 0xFF; pos[1] = 0x25;
    *reinterpret_cast<int32_t*>(&pos[2]) = 0;
    *reinterpret_cast<uint64_t*>(&pos[6]) = reinterpret_cast<uint64_t>(targetFunction) + prefix_skip + copied;
    tramp_off += 14;

    trampoline_.code = tramp;
    trampoline_.size = maxTramp;
    trampoline_.originalAddress = targetFunction;

    __builtin___clear_cache(reinterpret_cast<char*>(tramp), reinterpret_cast<char*>(tramp + tramp_off));

    return true;
}

bool HookPatch::patchFunction(void* targetFunction) {
    long pageSize = sysconf(_SC_PAGESIZE);
    uintptr_t addr = reinterpret_cast<uintptr_t>(targetFunction);
    uintptr_t pageStart = addr & ~(pageSize - 1);

    const size_t stubSize = 32;
    void* stubMem = mmap(nullptr, stubSize, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stubMem == MAP_FAILED) {
        std::cerr << "mmap(stub) failed: " << strerror(errno) << "\n";
        return false;
    }

    uint8_t* s = reinterpret_cast<uint8_t*>(stubMem);
    size_t off = 0;

    s[off++] = 0x49; s[off++] = 0xBA; // mov r10, imm64
    *reinterpret_cast<uint64_t*>(s + off) = static_cast<uint64_t>(nextId); // вставляем id
    off += 8;

    s[off++] = 0x48; s[off++] = 0xB8; //mov rax, imm64
    *reinterpret_cast<uint64_t*>(s + off) = reinterpret_cast<uint64_t>(&asm_wrapper);
    off += 8;

    s[off++] = 0xFF; s[off++] = 0xE0; // jmp rax

    __builtin___clear_cache(reinterpret_cast<char*>(stubMem),
                            reinterpret_cast<char*>(stubMem + off));

    uint8_t patch[14] = {
        0xFF, 0x25, //jmp QWORD PTR [RIP + 0]
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0
    };
    *reinterpret_cast<uint64_t*>(&patch[6]) = reinterpret_cast<uint64_t>(stubMem);

    if (mprotect(reinterpret_cast<void*>(pageStart), pageSize, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        std::cerr << "mprotect failed: " << strerror(errno) << "\n";
        munmap(stubMem, stubSize);
        return false;
    }

    memcpy(targetFunction, patch, sizeof(patch));

    if (mprotect(reinterpret_cast<void*>(pageStart), pageSize, PROT_READ | PROT_EXEC) == -1) {
        std::cerr << "mprotect restore failed: " << strerror(errno) << "\n";
    }

    char* origBegin = reinterpret_cast<char*>(targetFunction);
    char* origEnd = origBegin + JUMP_SIZE;
    __builtin___clear_cache(origBegin, origEnd);

    lastStub = stubMem;
    lastStubSize = stubSize;

    return true;
}


void HookPatch::restoreFunction() {
    if (!trampoline_.originalAddress || !trampoline_.code) return;

    long pageSize = sysconf(_SC_PAGESIZE);
    uintptr_t addr = reinterpret_cast<uintptr_t>(trampoline_.originalAddress);
    uintptr_t pageStart = addr & ~(pageSize - 1);
    if (mprotect(reinterpret_cast<void*>(pageStart), pageSize, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        std::cerr << "mprotect restore failed: " << strerror(errno) << "\n";
        return;
    }

    memcpy(trampoline_.originalAddress, trampoline_.code, JUMP_SIZE);

    if (mprotect(reinterpret_cast<void*>(pageStart), pageSize, PROT_READ | PROT_EXEC) == -1) {
        std::cerr << "mprotect restore2 failed: " << strerror(errno) << "\n";
    }
    char* origBegin = reinterpret_cast<char*>(trampoline_.originalAddress);
    char* origEnd = origBegin + JUMP_SIZE;
    __builtin___clear_cache(origBegin, origEnd);
}