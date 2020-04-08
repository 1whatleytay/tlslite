#include <tls/connection.h>

#include <tls/tls.h>
#include <tls/names.h>
#include <tls/private.h>

#include <stdio.h>
#include <assert.h>
#include <string.h>

#define TLS_SERVER_VERSION_MAJOR 3
#define TLS_SERVER_VERSION_MINOR 3

TlsCipherSuite cipherSuitesSupported[] = {
    TlsCipherSuiteRsaWithAes256CbcSha,
};

TlsCompressionMethod compressionMethodsSupported[] = {
    TlsCompressionMethodNone
};

bool tlsConnectionSendPlaintextHeader(TlsConnection *this, TlsContentType type, uint16_t size) {
    TlsPlaintextHeader plaintext;
    plaintext.version = this->version;
    plaintext.length = size;
    plaintext.type = type;

    uint32_t headerSize = tlsPlaintextHeaderGetSize();
    uint8_t headerData[headerSize];
    tlsPlaintextHeaderSerialize(&plaintext, headerData);

    return this->write(this->userData, headerData, headerSize);
}

bool tlsConnectionSendHandshakeHeader(TlsConnection *this, TlsHandshakeType type, uint32_t size) {
    printf("Sending Handshake %s\n", tlsHandshakeTypeName(type));

    TlsHandshakeHeader handshake;
    handshake.type = type;
    handshake.length = size;

    uint32_t headerSize = tlsHandshakeHeaderGetSize();
    uint8_t headerData[headerSize];
    tlsHandshakeHeaderSerialize(&handshake, headerData);

    return this->write(this->userData, headerData, headerSize);
}

static bool tlsConnectionHandleHandshake(TlsConnection *this, void *fragment, uint32_t size) {
    TlsHandshakeHeader header;
    void *data = tlsHandshakeHeaderParse(&header, fragment);
    uint32_t dataSize = size - tlsHandshakeHeaderGetSize();

    printf("Received Handshake: %s\n", tlsHandshakeTypeName(header.type));

    switch (header.type) {
        case TlsHandshakeTypeClientHello:
            if (!tlsConnectionHandleHandshakeClientHello(this, data, dataSize))
                assert(false);
            break;
        case TlsHandshakeTypeServerHello:
            if (!tlsConnectionHandleHandshakeServerHello(this, data, dataSize))
                assert(false);
            break;
        case TlsHandshakeTypeCertificate:
            if (!tlsConnectionHandleHandshakeCertificate(this, data, dataSize))
                assert(false);
            break;
        case TlsHandshakeTypeServerHelloDone:
            if (!tlsConnectionHandleHandshakeServerHelloDone(this, data, dataSize))
                assert(false);
            break;
        default:
            assert(false); // unimplemented
            break;
    }

    return true;
}

static bool tlsConnectionHandleAlert(TlsConnection *this, void *fragment, uint32_t size) {
    TlsAlert *alert = fragment;

    printf("Alert, level: %s, %s.\n", tlsAlertLevelName(alert->level), tlsAlertDescriptionName(alert->description));

    return true;
}

TlsError tlsConnectionInit(TlsConnection *this, TlsType type,
    TlsConnectionIoCallback read, TlsConnectionIoCallback write, void *userData) {
    this->type = type;

    // Meta
    this->version.major = TLS_SERVER_VERSION_MAJOR;
    this->version.minor = TLS_SERVER_VERSION_MINOR;
    this->supportedCipherSuiteCount =
        sizeof(cipherSuitesSupported) / sizeof(cipherSuitesSupported[0]);
    this->supportedCipherSuites = cipherSuitesSupported;
    this->supportedCompressionMethodCount =
        sizeof(compressionMethodsSupported) / sizeof(compressionMethodsSupported[0]);
    this->supportedCompressionMethods = compressionMethodsSupported;

    // Io
    this->userData = userData;
    this->read = read;
    this->write = write;

    if (type == TlsTypeClient) {
        if (!tlsConnectionInitHandshake(this))
            return TlsErrorFailedHandshake;
    }

    return TlsErrorNone;
}

TlsError tlsConnectionStart(TlsConnection *this) {
    while (true) {
        uint32_t plaintextSize = tlsPlaintextHeaderGetSize();
        uint8_t plaintextData[plaintextSize];
        if (!this->read(this->userData, plaintextData, plaintextSize)) {
            printf("Connection closed.");
            return TlsErrorNone;
        }

        TlsPlaintextHeader header;
        tlsPlaintextHeaderParse(&header, plaintextData);

        uint8_t fragment[header.length];
        memset(fragment, 0, header.length);
        if (!this->read(this->userData, fragment, header.length))
            assert(false);

        switch (header.type) {
            case TlsContentTypeHandshake:
                if (!tlsConnectionHandleHandshake(this, fragment, header.length))
                    return TlsErrorFailedHandshake;
                break;
            case TlsContentTypeAlert:
                if (!tlsConnectionHandleAlert(this, fragment, header.length))
                    return TlsErrorFailedAlert;
                break;
            default:
                assert(false); // unimplemented
                break;
        }
    }
}

void tlsConnectionClose(TlsConnection *this) {
    this->type = TlsTypeClosed;
}