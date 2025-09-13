#ifndef CLIENT_PIPE_H
#define CLIENT_PIPE_H

void safe_log(const char* msg, int fd);
int open_connection(char* path);
void close_connection(int fd);

#endif //END OF client.h