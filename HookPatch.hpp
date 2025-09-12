#ifndef HOOKPATCH_HPP
#define HOOKPATCH_HPP

#include <string>
#include <functional>
#include <vector>
#include <cstdint>

extern "C" uint64_t loggingWrapper_c(uint64_t* regs_buf, uint64_t nargs);
extern "C" void asm_wrapper() __attribute__((naked));
class HookPatch {
public:
    using LogCallback = std::function<void(const std::string&, const std::vector<uint64_t>&)>;

    HookPatch(const std::string& functionName, LogCallback callback = nullptr);
    ~HookPatch();

    // install/remove hook
    bool install();
    bool remove();
    bool isInstalled() const;

    // call original via trampoline
    template<typename FuncType, typename... Args>
    auto callOriginal(Args... args) -> decltype(std::declval<FuncType>()(args...));

    std::string functionName_;
    LogCallback logCallback_;

    void* getTrampolineAddr() const { return trampoline_.code; }
private:
    struct Trampoline {
        uint8_t* code = nullptr;
        size_t size = 0;
        void* originalAddress = nullptr;
    };
    Trampoline trampoline_;

    void* originalFunction_ = nullptr;
    bool installed_ = false;
    

    bool createTrampoline(void* targetFunction);
    bool patchFunction(void* targetFunction);
    void restoreFunction();

    static void defaultLogger(const std::string& funcName, const std::vector<uint64_t>& args);

    static const size_t JUMP_SIZE;
};

#endif // HOOKPATCH_HPP