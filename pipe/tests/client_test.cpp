#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define SOCK_PATH "/tmp/libhook.sock"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <MESSAGE>\n", argv[0]);
        return 1;
    }

    int fd;
    struct sockaddr_un addr;

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, SOCK_PATH);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("connect");
        close(fd);
        return 1;
    }

    const char* msg = argv[1];
    write(fd, msg, strlen(msg));
    write(fd, "\n", 1);
    
    char buf[1024];
    ssize_t r;
    while ((r = read(fd, buf, sizeof(buf)-1)) > 0) {
        buf[r] = '\0';
        printf("%s", buf);
    }

    close(fd);
    return 0;
}
