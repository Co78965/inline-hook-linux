#include "../pipe/client.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <limits.h>

#define PID   0
#define NAME  1

#define SOCK_PATH "/tmp/libhook.sock"

std::string findProcessByName(const char* processName)
{
    if (!processName) return "-1";

    DIR* directory = opendir("/proc/");
    if (!directory) return "-1";

    struct dirent* procDirs;
    while ((procDirs = readdir(directory)) != NULL)
    {
        if (procDirs->d_type != DT_DIR) continue;

        pid_t pid = atoi(procDirs->d_name);
        if (pid <= 0) continue;

        char exePath[PATH_MAX];
        snprintf(exePath, sizeof(exePath), "/proc/%s/exe", procDirs->d_name);

        char exeBuf[PATH_MAX];
        ssize_t len = readlink(exePath, exeBuf, sizeof(exeBuf) - 1);
        if (len == -1) continue;
        exeBuf[len] = '\0';

        // Получаем имя файла
        char* exeName = strrchr(exeBuf, '/');
        exeName = exeName ? exeName + 1 : exeBuf;

        if (strcmp(exeName, processName) == 0)
        {
            closedir(directory);
            return std::to_string(pid);
        }
    }

    closedir(directory);
    return "-1";
}

bool load_dll(int type, const std::string& proc_info)
{
    std::string target_pid;
    if (type == PID)
        target_pid = proc_info;
    else if (type == NAME)
        target_pid = findProcessByName(proc_info.c_str());
    else
        return false;

    std::string so_path = "/home/ivan/projects/trspo/lab_1_dop/so_loader/libempty.so";
    std::string cmd = "bash /home/ivan/projects/trspo/lab_1_dop/so_loader/loader.sh " + target_pid + " " + so_path;
    int ret = system(cmd.c_str());
    return ret == 0;
}

int main(int argc, char* argv[])
{
    if (argc < 5)
    {
        std::cout << "Usage:\n";
        std::cout << "  connect [pipe_name]\n";
        std::cout << "  send -pid <PID> <cmd> <value>\n";
        std::cout << "  send -name <ProcessName> <cmd> <value>\n";
        return 0;
    }

    int type;
    std::string proc_info;
    std::string msg;

    if (!strcmp(argv[1], "-pid") || !strcmp(argv[1], "-name"))
    {
        type = !strcmp(argv[1], "-pid") ? PID : NAME;
        proc_info = argv[2];
        msg = std::string(argv[3]) + "~" + std::string(argv[4]);
    }
    else if (!strcmp(argv[3], "-pid") || !strcmp(argv[3], "-name"))
    {
        type = !strcmp(argv[3], "-pid") ? PID : NAME;
        proc_info = argv[4];
        msg = std::string(argv[1]) + "~" + std::string(argv[2]);
    }
    else
    {
        std::cerr << "Invalid arguments\n";
        return 1;
    }

    if (!load_dll(type, proc_info))
    {
        std::cerr << "Failed to load .so into target process\n";
        return 1;
    }

    int fd;
    struct sockaddr_un addr;
    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
    {
        perror("socket");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1)
    {
        perror("connect");
        close(fd);
        return 1;
    }

    write(fd, msg.c_str(), msg.size());
    write(fd, "\n", 1);

    char buf[1024];
    ssize_t r;
    while ((r = read(fd, buf, sizeof(buf) - 1)) > 0)
    {
        buf[r] = '\0';
        printf("%s", buf);
    }

    close(fd);
    return 0;
}
