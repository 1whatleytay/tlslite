#pragma once

#include <stdint.h>
#include <stdlib.h>

typedef uint16_t Port;
typedef unsigned char Address[4];

typedef enum {
    SocketErrorNone = 0,
    SocketErrorCannotCreateSocket,
    SocketErrorCannotConnect,
    SocketErrorCannotBind,
    SocketErrorCannotListen,
    SocketErrorCannotAccept,
    SocketErrorCannotRead,
    SocketErrorCannotWrite,
} SocketError;

typedef enum {
    SocketTypeClosed,
    SocketTypeServer,
    SocketTypeConnection,
    SocketTypeClient,
} SocketType;

typedef struct {
    int id;
    SocketType type;
} Socket;

SocketError socketConnect(Socket *this, Address address, Port port);
SocketError socketHost(Socket *this, Port port);
SocketError socketListen(Socket *this, Socket *that);
SocketError socketRead(Socket *this, void *data, size_t size);
SocketError socketWrite(Socket *this, void *data, size_t size);
void socketClose(Socket *this);
