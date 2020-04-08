#include <sockets/callbacks.h>

#include <sockets/sockets.h>

#include <stdio.h>

bool socketReadCallback(void *socket, void *data, size_t size) {
    Socket *this = socket;

    return socketRead(this, data, size) == SocketErrorNone;
}
bool socketWriteCallback(void *socket, void *data, size_t size) {
    Socket *this = socket;

    return socketWrite(this, data, size) == SocketErrorNone;
}