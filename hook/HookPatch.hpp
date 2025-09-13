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
    void* stub;         // <--- добавлено
    size_t stubSize;    // <--- добавлено
};

class HookPatch {
public:
    HookPatch(LogCallback callback = nullptr);
    ~HookPatch();
    int nextId = 0;
    // install/remove hook
    bool install(std::string functionName) ;
    bool remove();
    bool isInstalled() const;

    // call original via trampoline
    template<typename FuncType, typename... Args>
    auto callOriginal(Args... args) -> decltype(std::declval<FuncType>()(args...));

    std::string functionName_;
    LogCallback logCallback_;
    static void defaultLogger(const std::string funcName);
    void* getTrampolineAddr() const { return trampoline_.code; }
private:
    void* originalFunction_ = nullptr;
    bool installed_ = false;
    struct Trampoline trampoline_;

    void* lastStub = nullptr;
    size_t lastStubSize = 0;
    unsigned int installedId = UINT_MAX; // сохраняем id установленного хука

    bool createTrampoline(void* targetFunction);
    bool patchFunction(void* targetFunction);
    void restoreFunction();
    static const size_t JUMP_SIZE;
};

class HookController {
protected:
    static HookController* hookController;
    HookPatch* hookPatch;

    HookController(LogCallback callback) {
        hookPatch = new HookPatch(nullptr);
    }

public:
    HookController(HookController& other) = delete;
    void operator=(const HookController&) = delete;

    static HookController* GetHookController();
    HookPatch* GetHookPatch();
};

#endif // HOOKPATCH_HPP