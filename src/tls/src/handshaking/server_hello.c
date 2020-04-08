#include <tls/private.h>

#include <tls/handshakes.h>

#include <assert.h>

bool tlsConnectionHandleHandshakeServerHello(TlsConnection *this, void *data, uint32_t size) {
    assert(this->type == TlsTypeClient);

    TlsHandshakeServerHello serverHello;
    tlsHandshakeServerHelloParse(&serverHello, data, size);

    return true;
}