#include <tls/tls.h>

#include <encryption/random.h>

#include <string.h>

void *tlsPlaintextHeaderParse(TlsPlaintextHeader *this, void *data) {
    this->type = *(TlsContentType *)data;
    data += sizeof(TlsContentType);
    this->version = *(TlsVersion *)data;
    data += sizeof(TlsVersion);
    this->length = SWAP_ENDIAN_16(*(uint16_t *)data);
    data += sizeof(uint16_t);

    return data;
}


uint32_t tlsPlaintextHeaderGetSize() {
    return sizeof(TlsContentType)
        + sizeof(TlsVersion)
        + sizeof(uint16_t);
}

void tlsPlaintextHeaderSerialize(TlsPlaintextHeader *this, void *data) {
    *(TlsContentType *)data = this->type;
    data += sizeof(TlsContentType);
    *(TlsVersion *)data = this->version;
    data += sizeof(TlsVersion);
    *(uint16_t *)data = SWAP_ENDIAN_16(this->length);
    data += sizeof(uint16_t);
}

void *tlsHandshakeHeaderParse(TlsHandshakeHeader *this, void *data) {
    this->type = *(TlsHandshakeType *)data;
    data += sizeof(TlsHandshakeType);
    this->length = tlsUint24Unpack(data);
    data += sizeof(TlsUint24);

    return data;
}

uint32_t tlsHandshakeHeaderGetSize() {
    return sizeof(TlsHandshakeType)
        + sizeof(TlsUint24);
}

void tlsHandshakeHeaderSerialize(TlsHandshakeHeader *this, void *data) {
    *(TlsHandshakeType *)data = this->type;
    data += sizeof(TlsHandshakeType);
    tlsUint24Pack(data, this->length);
    data += sizeof(TlsUint24);
}

void *tlsExtensionHeaderParse(TlsExtensionHeader *this, void *data) {
    this->type = *(TlsExtensionType *)data;
    data += sizeof(TlsExtensionType);
    this->length = SWAP_ENDIAN_16(*(uint16_t *)data);
    data += sizeof(uint16_t);

    return data;
}

uint32_t tlsExtensionHeaderGetSize() {
    return sizeof(TlsExtensionType)
        + sizeof(uint16_t);
}

void tlsExtensionHeaderSerialize(TlsExtensionHeader *this, void *data) {
    *(TlsExtensionType *)data = this->type;
    data += sizeof(TlsExtensionType);
    *(uint16_t *)data = SWAP_ENDIAN_16(this->length);
    data += sizeof(uint16_t);
}

uint8_t randomLastBytes[] = {
    0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00
};

void tlsRandomFill(TlsRandom random) {
    randomInit((uint8_t *)random, sizeof(TlsRandom));
}

void tlsRandomSetVersion(TlsRandom random, TlsVersion version) {
    if (version.major != 3 || version.minor != 4) {
        memcpy(random + sizeof(TlsRandom) - sizeof(randomLastBytes), randomLastBytes, sizeof(randomLastBytes));
    }

    if (version.major == 3 && version.minor == 3) {
        random[sizeof(TlsRandom) - 1] = 0x01;
    }
}

void tlsUint24Pack(TlsUint24 this, uint32_t value) {
    this[2] = value & 0xFFu;
    this[1] = (value >> 8u) & 0xFFu;
    this[0] = value >> 16u;
}

uint32_t tlsUint24Unpack(const TlsUint24 this) {
    return (this[0] << 16u) | (this[1] << 8u) | this[2];
}
