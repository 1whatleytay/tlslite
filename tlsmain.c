#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>

#include <sockets/sockets.h>
#include <sockets/callbacks.h>

#include <tls/connection.h>

int main() {
    Socket socket;

    Port port = 443; // https
    Address address = { 216, 58, 211, 110 }; // google

    if (socketConnect(&socket, address, port) != SocketErrorNone)
        assert(false);

    TlsConnection connection;

    if (tlsConnectionInit(&connection, TlsTypeClient, socketReadCallback, socketWriteCallback, &socket) != TlsErrorNone)
        assert(false);

    if (tlsConnectionStart(&connection) != TlsErrorNone)
        assert(false);

    tlsConnectionClose(&connection);
    socketClose(&socket);

    return 0;
}
