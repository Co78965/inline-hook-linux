// fifo_client.cpp
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "client.h"

void safe_log(const char* msg, int fd) {
    syscall(SYS_write, fd, msg, strlen(msg));
}

int open_connection(char* path){
    return syscall(SYS_open, path, O_RDWR);
}

void close_connection(int fd){
    syscall(SYS_close, fd);
}