#include <sockets/sockets.h>

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <errno.h>

#define SOCKETS_DEFAULT_BACKLOG_SIZE 5

static void socket_init(Socket *this) {
    this->id = 0;
    this->type = SocketTypeClosed;
}

SocketError socketConnect(Socket *this, Address address, Port port) {
    socket_init(this);
    this->type = SocketTypeClient;

    this->id = socket(AF_INET, SOCK_STREAM, 0);

    if (this->id == -1)
        return SocketErrorCannotCreateSocket;

    struct sockaddr_in addressIn;
    memset(&addressIn, 0, sizeof(addressIn));
    addressIn.sin_family = AF_INET;
    memcpy(&addressIn.sin_addr.s_addr, address, sizeof(Address));
    addressIn.sin_port = htons(port);

    if (connect(this->id, (struct sockaddr *)&addressIn, sizeof(addressIn)))
        return SocketErrorCannotConnect;

    return SocketErrorNone;
}

SocketError socketHost(Socket *this, Port port) {
    socket_init(this);
    this->type = SocketTypeServer;

    this->id = socket(AF_INET, SOCK_STREAM, 0);
    if (this->id == -1)
        return SocketErrorCannotCreateSocket;

    struct sockaddr_in addressIn;
    memset(&addressIn, 0, sizeof(addressIn));
    addressIn.sin_family = AF_INET;
    addressIn.sin_port = htons(port);
    addressIn.sin_addr.s_addr = INADDR_ANY;

    if (bind(this->id, (struct sockaddr *)&addressIn, sizeof(addressIn)) == -1)
        return SocketErrorCannotBind;

    if (listen(this->id, SOCKETS_DEFAULT_BACKLOG_SIZE) == -1)
        return SocketErrorCannotListen;

    return SocketErrorNone;
}

SocketError socketListen(Socket *this, Socket *that) {
    socket_init(that);
    that->type = SocketTypeConnection;

    int id = accept(this->id, NULL, NULL);

    if (id == -1)
        return SocketErrorCannotAccept;

    that->id = id;

    return SocketErrorNone;
}

SocketError socketRead(Socket *this, void *data, size_t size) {
    ssize_t bytes = recv(this->id, data, size, 0);

    if (bytes <= 0)
        return SocketErrorCannotRead;

    return SocketErrorNone;
}

SocketError socketWrite(Socket *this, void *data, size_t size) {
    ssize_t bytes = send(this->id, data, size, 0);

    if (bytes <= 0)
        return SocketErrorCannotWrite;

    return SocketErrorNone;
}

void socketClose(Socket *this) {
    close(this->id);
    this->type = SocketTypeClosed;
}