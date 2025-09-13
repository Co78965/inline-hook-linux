#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <string>
#include <stdlib.h>

#include "server.h"
#include "../hook/HookPatch.hpp"

#define SOCK_PATH "/tmp/libhook.sock"

HookController* hookController;
int client_fd = -1;

void safe_log(const char* msg) {
    if (client_fd != -1) {
        write(client_fd, msg, strlen(msg));
    } else {
        syscall(SYS_write, 2, msg, strlen(msg));
    }
}

void parse_message(std::string msg)
{
    auto pos = msg.find('~');
    std::string cmd;
    std::string value;

    if (pos != std::string::npos) {
        cmd = msg.substr(0, pos);
        value = msg.substr(pos + 1);
    } else {
        safe_log("invalid format, use cmd~value\n");
        return;
    }

    if(cmd == "-hide")
    {
        safe_log("=== hide mode ===\n");
    }
    else if (cmd == "-func")
    {
        HookPatch* hookPatch = hookController->GetHookPatch();

        safe_log("=== log mode ===\n");

        if(!hookPatch->install(value)){
            safe_log("[ERROR] Patched Unsuccessful!\n");
            return;
        }
    }
    else
    {
        safe_log("incorrect command [-hide, -func]\n");
    }
}

void server_stop(){
    safe_log("[.so] Unloaded (minimal safe)\n");
    close(client_fd);
    client_fd = -1;
}

void server(){
    hookController = HookController::GetHookController(safe_log);

    int server_fd;
    struct sockaddr_un addr;
    unlink(SOCK_PATH);

    if ((server_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        return;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, SOCK_PATH);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("bind");
        close(server_fd);
        return;
    }

    if (listen(server_fd, 5) == -1) {
        perror("listen");
        close(server_fd);
        return;
    }

    safe_log("Server: socket created, waiting for clients...\n");

    while (1) {
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd == -1) {
            perror("accept");
            continue;
        }

        char buf[1024];
        ssize_t r;
        r = read(client_fd, buf, sizeof(buf)-1);
        buf[r] = '\0';
        char* p = strchr(buf, '\n');
        if (p) *p = '\0';
        parse_message(std::string(buf));
    }
}
