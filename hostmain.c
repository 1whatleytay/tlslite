#include <sockets/sockets.h>
#include <sockets/callbacks.h>

#include <tls/connection.h>

int main() {
    Socket socket;

    socketHost(&socket, 443);

    Socket cSocket;
    socketListen(&socket, &cSocket);

    TlsConnection connection;
    tlsConnectionInit(&connection, TlsTypeServer, socketReadCallback, socketWriteCallback, &cSocket);
    tlsConnectionStart(&connection);

    tlsConnectionClose(&connection);
    socketClose(&cSocket);
    socketClose(&socket);
}