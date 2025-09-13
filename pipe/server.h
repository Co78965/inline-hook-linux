#ifndef SERVER_PIPE_H
#define SERVER_PIPE_H

#define PIPE "/tmp/libhook_fifo"

void safe_log(const char* msg);
void server();
void server_stop();

#endif //END OF server.h