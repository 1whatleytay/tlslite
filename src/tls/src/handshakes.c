#include <tls/handshakes.h>

#include <stdlib.h>
#include <string.h>

void tlsHandshakeClientHelloParse(TlsHandshakeClientHello *this, void *data, uint32_t size) {
    void *start = data;

    this->version = data;
    data += sizeof(TlsVersion);

    this->random = data;
    data += sizeof(TlsRandom);

    this->sessionIdSize = *(uint8_t *)data;
    data += sizeof(uint8_t);
    this->sessionId = data;
    data += this->sessionIdSize;

    uint16_t cipherSuitesSize = ntohs(*(uint16_t *)data);
    data += sizeof(uint16_t);
    this->cipherSuiteCount = cipherSuitesSize / 2;
    this->cipherSuites = data;
    data += cipherSuitesSize;

    this->compressionMethodsSize = *(uint8_t *)data;
    data += sizeof(uint8_t);
    this->compressionMethods = data;
    data += this->compressionMethodsSize;

    if (((uintptr_t)data - (uintptr_t)start) < size) {
        this->extensionsSize = SWAP_ENDIAN_16(*(uint16_t *) data);
        data += sizeof(uint16_t);
        this->extensions = data;
        data += this->extensionsSize;
    } else {
        this->extensionsSize = 0;
        this->extensions = NULL;
    }
}

uint32_t tlsHandshakeClientHelloSerializeGetSize(TlsHandshakeClientHello *this) {
    return sizeof(TlsVersion)
        + sizeof(TlsRandom)
        + sizeof(uint8_t) + this->sessionIdSize
        + sizeof(uint16_t) + this->cipherSuiteCount * sizeof(TlsCipherSuite)
        + sizeof(uint8_t) + this->compressionMethodsSize
        + (this->extensions ? (sizeof(uint16_t) + this->extensionsSize) : 0);
}

void tlsHandshakeClientHelloSerialize(TlsHandshakeClientHello *this, void *data) {
    void *start = data;

    *(TlsVersion *)data = *this->version;
    data += sizeof(TlsVersion);

    memcpy(data, this->random, sizeof(TlsRandom));
    data += sizeof(TlsRandom);

    *(uint8_t *)data = this->sessionIdSize;
    data += sizeof(uint8_t);
    memcpy(data, this->sessionId, this->sessionIdSize);
    data += this->sessionIdSize;

    *(uint16_t *)data = htons(this->cipherSuiteCount * sizeof(TlsCipherSuite));
    data += sizeof(uint16_t);
    // tls is already htons in the definition
    memcpy(data, this->cipherSuites, this->cipherSuiteCount * sizeof(TlsCipherSuite));
    data += this->cipherSuiteCount * sizeof(TlsCipherSuite);

    *(uint8_t *)data = this->compressionMethodsSize;
    data += sizeof(uint8_t);
    memcpy(data, this->compressionMethods, this->compressionMethodsSize);
    data += this->compressionMethodsSize;

    if (this->extensions) {
        *(uint16_t *)data = SWAP_ENDIAN_16(this->extensionsSize);
        data += sizeof(uint16_t);
        memcpy(data, this->extensions, this->extensionsSize);
        data += this->extensionsSize;
    }
}

void tlsHandshakeServerHelloParse(TlsHandshakeServerHello *this, void *data, uint32_t size) {
    void *start = data;

    this->version = data;
    data += sizeof(TlsVersion);

    this->random = data;
    data += sizeof(TlsRandom);

    this->sessionIdSize = *(uint8_t *)data;
    data += sizeof(uint8_t);
    this->sessionId = data;
    data += this->sessionIdSize;

    this->cipherSuite = *(TlsCipherSuite *)data;
    data += sizeof(TlsCipherSuite);

    this->compressionMethod = *(TlsCompressionMethod *)data;
    data += sizeof(TlsCompressionMethod);

    if (((uintptr_t)data - (uintptr_t)start) < size) {
        this->extensionsSize = SWAP_ENDIAN_16(*(uint16_t *) data);
        data += sizeof(uint16_t);
        this->extensions = data;
        data += this->extensionsSize;
    } else {
        this->extensionsSize = 0;
        this->extensions = NULL;
    }
}

uint32_t tlsHandshakeServerHelloSerializeGetSize(TlsHandshakeServerHello *this) {
    return sizeof(TlsVersion)
        + sizeof(TlsRandom)
        + sizeof(uint8_t) + this->sessionIdSize
        + sizeof(uint16_t)
        + sizeof(uint8_t)
        + (this->extensions ? (sizeof(uint16_t) + this->extensionsSize) : 0);
}

void tlsHandshakeServerHelloSerialize(TlsHandshakeServerHello *this, void *data) {
    *(TlsVersion *)data = *this->version;
    data += sizeof(TlsVersion);

    memcpy(data, this->random, sizeof(TlsRandom));
    data += sizeof(TlsRandom);

    *(uint8_t *)data = this->sessionIdSize;
    data += sizeof(uint8_t);
    memcpy(data, this->sessionId, this->sessionIdSize);
    data += this->sessionIdSize;

    *(TlsCipherSuite *)data = this->cipherSuite;
    data += sizeof(TlsCipherSuite);

    *(TlsCompressionMethod *)data = this->compressionMethod;
    data += sizeof(TlsCompressionMethod);

    if (this->extensions) {
        *(uint16_t *)data = SWAP_ENDIAN_16(this->extensionsSize);
        data += sizeof(uint16_t);
        memcpy(data, this->extensions, this->extensionsSize);
        data += this->extensionsSize;
    }
}

void tlsHandshakeCertificatesParse(TlsHandshakeCertificates *this, void *data, uint32_t size) {
    TlsUint24 certificatesSize24;
    memcpy(certificatesSize24, data, sizeof(TlsUint24));
    this->certificatesSize = tlsUint24Unpack(certificatesSize24);
    data += sizeof(TlsUint24);

    if (this->certificatesSize > 0)
        this->firstCertificate = data;
    else
        this->firstCertificate = NULL;
}

void *tlsHandshakeCertificateParse(TlsHandshakeCertificates *this, void *data, TlsHandshakeCertificate *certificate) {
    TlsUint24 certificateSize24;
    memcpy(certificateSize24, data, sizeof(TlsUint24));
    certificate->size = tlsUint24Unpack(certificateSize24);
    data += sizeof(TlsUint24);

    certificate->data = data;
    data += certificate->size;

    void *next = data;

    uintptr_t sizeParsed = next - this->firstCertificate;
    if (sizeParsed >= this->certificatesSize)
        return NULL;

    return next;
}

uint32_t tlsHandshakeCertificatesSerializeGetSize(TlsHandshakeCertificate *certificates, uint32_t count) {
    uint32_t sum = 0;

    for (uint32_t a = 0; a < count; a++) {
        sum += certificates[a].size + sizeof(TlsUint24);
    }

    return sum + sizeof(TlsUint24);
}

void tlsHandshakeCertificatesSerialize(TlsHandshakeCertificate *certificates, uint32_t count, void *data) {
    void *start = data;
    data += sizeof(TlsUint24); // full certificate size

    uint32_t certificatesSize = 0;

    for (uint32_t a = 0; a < count; a++) {
        TlsUint24 size;
        tlsUint24Pack(size, certificates[a].size);
        memcpy(data, size, sizeof(size));
        data += sizeof(TlsUint24);

        memcpy(data, certificates[a].data, certificates[a].size);
        data += certificates[a].size;

        certificatesSize += certificates[a].size + sizeof(TlsUint24);
    }

    TlsUint24 size24;
    tlsUint24Pack(size24, certificatesSize);
    memcpy(start, size24, sizeof(size24));
}
