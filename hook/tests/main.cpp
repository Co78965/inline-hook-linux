#include "../HookPatch.hpp"
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <sys/stat.h>
#include <sstream>
#include <iostream>

static void safe_log(const char* prefix, const char* path) {
    char buf[512];
    int n = snprintf(buf, sizeof(buf), "%s %s\n", prefix, path ? path : "(null)");
    if (n > 0) {
        ssize_t w = write(2, buf, static_cast<size_t>(n));
        (void)w;
    }
}

int main() {
    HookController* hookController = HookController::GetHookController(printf);
    HookPatch* hookPatch = hookController->GetHookPatch();

    if (!hookPatch->install("open")) {
        write(2, "Failed to install hook\n", 23);
        return 1;
    }

    if (!hookPatch->install("puts")) {
        write(2, "Failed to install hook\n", 23);
        return 1;
    }

    puts("check!");

    // --- Тест 1: open + write + close (создание файла)
    const char* filename1 = "hook_test1.txt";
    int fd = open(filename1, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd == -1) {
        safe_log("[ERROR] open failed for", filename1);
    } else {
        const char* text = "Hello from open() test\n";
        write(fd, text, strlen(text));
        close(fd);
    }

    // // --- Тест 2: fopen (внутри будет вызван open)
    // const char* filename2 = "hook_test2.txt";
    // FILE* f = fopen(filename2, "w");
    // if (!f) {
    //     safe_log("[ERROR] fopen failed for", filename2);
    // } else {
    //     fputs("Hello from fopen() test\n", f);
    //     fclose(f);
    // }

    // // Удаляем хук и делаем ещё один вызов open чтобы убедиться, что после remove всё нормально
    // hook.remove();
    // int fd2 = open("hook_after_remove.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    // if (fd2 != -1) {
    //     const char* txt = "After remove\n";
    //     write(fd2, txt, strlen(txt));
    //     close(fd2);
    // }

    // write(2, "Test finished\n", 14);
    return 0;
}
