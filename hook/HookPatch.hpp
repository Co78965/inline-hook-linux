#ifndef HOOKPATCH_HPP
#define HOOKPATCH_HPP

#include <string>
#include <functional>
#include <vector>
#include <cstdint>
#include <climits>

extern "C" uint64_t loggingWrapper_c(unsigned int id);
extern "C" void asm_wrapper() __attribute__((naked));

extern std::wstring hiddenFile;
using LogCallback = std::function<void(const std::string)>;
using SendMessageFunc = std::function<void(const char*)>;

enum HookMode
{ 
    LOG_ONLY,
    HIDE_FILE 
};

struct Trampoline {
    uint8_t* code = nullptr;
    size_t size = 0;
    void* originalAddress = nullptr;
};

struct PatchInfo {
    void* originalAddress;
    struct Trampoline trampoline;
    char functionName[100];
    int id;
    HookMode mode;
    void* stub;
    size_t stubSize;
};

class HookPatch {
public:
    static const size_t JUMP_SIZE;

    HookPatch(LogCallback callback = nullptr, SendMessageFunc send_func = nullptr);
    ~HookPatch();

    bool install(std::string functionName);
    void removeAll();

    HookPatch(const HookPatch&) = delete;
    HookPatch& operator=(const HookPatch&) = delete;

    HookPatch(HookPatch&&) = delete;
    HookPatch& operator=(HookPatch&&) = delete;

    static void defaultLogger(const std::string& funcName);

    void* lastStub = nullptr;
    size_t lastStubSize = 0;

    Trampoline trampoline_{};
    void* originalFunction_ = nullptr;
    std::string functionName_;
    static SendMessageFunc sendMessage_;

private:
    bool createTrampoline(void* targetFunction);
    bool patchFunction(void* targetFunction);
    void restoreFunction();

    LogCallback logCallback_;
    bool installed_ = false;
    unsigned int nextId = 0;
};


class HookController {
protected:
    static HookController* hookController;
    HookPatch* hookPatch;

    HookController(LogCallback callback, SendMessageFunc send_func) {
        hookPatch = new HookPatch(callback, send_func);
    }

public:
    static HookController* GetHookController(SendMessageFunc send_func) {
        if (!hookController) {
            hookController = new HookController(nullptr, send_func);
        }
        return hookController;
    }

    HookPatch* GetHookPatch() { return hookPatch; }
};

#endif // HOOKPATCH_HPP