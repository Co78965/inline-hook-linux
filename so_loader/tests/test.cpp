#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <sys/stat.h>
#include <sstream>
#include <iostream>

int main() {
    printf("sleeper started, pid=%d\n", getpid());
    fflush(stdout);

    for (int i = 0; i < 20; ++i) {
        printf("%d\n", i);
        sleep(1);
    }

    printf("end wait\n");

    const char* filename1 = "hook_test1.txt";
    int fd = open(filename1, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    printf("after open\n");
    if (fd == -1) {
        printf("[ERROR] open failed for %s", filename1);
    } else {
        const char* text = "Hello from open() test\n";
        write(fd, text, strlen(text));
        close(fd);
    }
    return 0;
}