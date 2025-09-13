#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "../server.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        const char* usage = "Usage: fifo_server <FIFO_PATH>\n";
        syscall(SYS_write, 2, usage, strlen(usage));
        return 1;
    }

    server();

    return 0;
}