#include <tls/private.h>

#include <tls/handshakes.h>

#include <assert.h>

bool tlsConnectionInitHandshake(TlsConnection *this) {
    TlsRandom random;
    tlsRandomFill(random);

    TlsHandshakeClientHello clientHello;
    clientHello.version = &this->version;
    clientHello.random = &random;
    clientHello.sessionIdSize = 0;
    clientHello.sessionId = NULL;
    clientHello.cipherSuiteCount = this->supportedCipherSuiteCount;
    clientHello.cipherSuites = this->supportedCipherSuites;
    clientHello.compressionMethodsSize = this->supportedCompressionMethodCount;
    clientHello.compressionMethods = this->supportedCompressionMethods;
    clientHello.extensionsSize = 0;
    clientHello.extensions = NULL;

    uint32_t clientHelloSize = tlsHandshakeClientHelloSerializeGetSize(&clientHello);
    uint8_t clientHelloData[clientHelloSize];
    tlsHandshakeClientHelloSerialize(&clientHello, clientHelloData);

    if (!tlsConnectionSendPlaintextHeader(this, TlsContentTypeHandshake,
        clientHelloSize + tlsHandshakeHeaderGetSize()))
        assert(false);

    if (!tlsConnectionSendHandshakeHeader(this, TlsHandshakeTypeClientHello, clientHelloSize))
        assert(false);

    if (!this->write(this->userData, clientHelloData, clientHelloSize))
        assert(false);

    return true;
}