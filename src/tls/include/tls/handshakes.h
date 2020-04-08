#pragma once

#include <tls/tls.h>

typedef struct {
    TlsVersion *version;
    TlsRandom *random;
    uint8_t sessionIdSize;
    uint8_t *sessionId;
    uint16_t cipherSuiteCount;
    TlsCipherSuite *cipherSuites;
    uint8_t compressionMethodsSize;
    TlsCompressionMethod *compressionMethods;
    uint16_t extensionsSize;
    void *extensions;
} TlsHandshakeClientHello;

typedef struct {
    TlsVersion *version;
    TlsRandom *random;
    uint8_t sessionIdSize;
    uint8_t *sessionId;
    TlsCipherSuite cipherSuite;
    TlsCompressionMethod compressionMethod;
    uint16_t extensionsSize;
    void *extensions;
} TlsHandshakeServerHello;

typedef struct {
    uint32_t size;
    uint8_t *data;
} TlsHandshakeCertificate;

typedef struct {
    uint32_t certificatesSize;
    void *firstCertificate;
} TlsHandshakeCertificates;

void tlsHandshakeClientHelloParse(TlsHandshakeClientHello *this, void *data, uint32_t size);
uint32_t tlsHandshakeClientHelloSerializeGetSize(TlsHandshakeClientHello *this);
void tlsHandshakeClientHelloSerialize(TlsHandshakeClientHello *this, void *data);

void tlsHandshakeServerHelloParse(TlsHandshakeServerHello *this, void *data, uint32_t size);
uint32_t tlsHandshakeServerHelloSerializeGetSize(TlsHandshakeServerHello *this);
void tlsHandshakeServerHelloSerialize(TlsHandshakeServerHello *this, void *data);

void tlsHandshakeCertificatesParse(TlsHandshakeCertificates *this, void *data, uint32_t size);
void *tlsHandshakeCertificateParse(TlsHandshakeCertificates *this, void *data, TlsHandshakeCertificate *certificate);
uint32_t tlsHandshakeCertificatesSerializeGetSize(TlsHandshakeCertificate *certificates, uint32_t count);
void tlsHandshakeCertificatesSerialize(TlsHandshakeCertificate *certificates, uint32_t count, void *data);
