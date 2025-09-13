#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "../pipe/server.h"

static pthread_t server_thread;
static volatile int stop_flag = 0;

static void* server_thread_func(void*) {
    server();
    return nullptr;
}

__attribute__((constructor))
void on_load() {
    stop_flag = 0;
    if (pthread_create(&server_thread, nullptr, server_thread_func, nullptr) != 0) {
        perror("pthread_create");
        exit(1);
    }
}

__attribute__((destructor))
void on_unload() {
    stop_flag = 1;
    server_stop();
    pthread_join(server_thread, nullptr);
}
