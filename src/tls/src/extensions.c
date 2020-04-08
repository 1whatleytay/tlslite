#include <tls/extensions.h>

#include <tls/tls.h>

#include <string.h>

void tlsExtensionServerNamesParse(TlsExtensionServerNames *this, void *data, uint32_t size) {
    this->serverNameSize = SWAP_ENDIAN_16(*(uint16_t *)data);
    data += sizeof(uint16_t);

    if (this->serverNameSize > 0)
        this->firstServerName = data;
    else
        this->firstServerName = NULL;
}

void *tlsExtensionServerNameParse(TlsExtensionServerNames *this, void *data, TlsExtensionServerName *name) {
    name->nameType = *(uint8_t *)data;
    data += sizeof(uint8_t);
    name->nameLength = SWAP_ENDIAN_16(*(uint16_t *)data);
    data += sizeof(uint16_t);
    name->name = data;
    data += name->nameLength;

    void *next = data;

    uintptr_t sizeParsed = next - this->firstServerName;
    if (sizeParsed >= this->serverNameSize)
        return NULL;

    return next;
}

//uint32_t tlsExtensionServerNameSerializeGetSize(TlsExtensionServerName *this, void *data) {
//    return sizeof(uint8_t)
//        + sizeof(uint16_t)
//        + this->nameLength;
//}
//
//void tlsExtensionServerNameSerialize(TlsExtensionServerName *this, void *data) {
//    *(uint8_t *)data = this->nameType;
//    data += sizeof(uint8_t);
//    *(uint16_t *)data = SWAP_ENDIAN_16(this->nameLength);
//    data += sizeof(uint16_t);
//    memcpy(data, this->name, this->nameLength);
//    data += this->nameLength;
//}

void tlsExtensionSupportedGroupsParse(TlsExtensionSupportedGroups *this, void *data, uint32_t size) {
    uint16_t supportedGroupsSize = SWAP_ENDIAN_16(*(uint16_t *)data);
    this->supportedGroupCount = supportedGroupsSize / sizeof(TlsSupportedGroup);
    data += sizeof(uint16_t);
    this->supportedGroups = data;
    data += supportedGroupsSize;
}
//uint32_t tlsExtensionSupportedGroupsSerializeGetSize(TlsExtensionSupportedGroups *this, void *data) {
//
//}
//void tlsExtensionSupportedGroupsSerialize(TlsExtensionSupportedGroups *this, void *data) {
//
//}

void tlsExtensionProtocolNamesParse(TlsExtensionProtocolNames *this, void *data, uint32_t size) {
    this->protocolSize = SWAP_ENDIAN_16(*(uint16_t *)data);
    data += sizeof(uint16_t);

    if (this->protocolSize > 0)
        this->firstProtocol = data;
    else
        this->firstProtocol = NULL;
}

void *tlsExtensionProtocolNameParse(TlsExtensionProtocolNames *this, void *data, TlsExtensionProtocolName *name) {
    name->protocolSize = *(uint8_t *)data;
    data += sizeof(uint8_t);
    name->protocol = data;
    data += name->protocolSize;

    void *next = data;

    uintptr_t sizeParsed = next - this->firstProtocol;
    if (sizeParsed >= this->protocolSize)
        return NULL;

    return next;
}

void tlsExtensionStatusRequestParse(TlsExtensionStatusRequest *this, void *data, uint32_t size) {
    this->statusType = *(uint8_t *)data;
    data += sizeof(uint8_t);

    this->responderIdSize = SWAP_ENDIAN_16(*(uint16_t *)data);
    data += sizeof(uint16_t);
    if (this->responderIdSize > 0)
        this->firstResponderId = data;
    else
        this->firstResponderId = NULL;
    data += this->responderIdSize;

    this->extensionsSize = *(uint16_t *)data;
    if (this->extensionsSize > 0)
        this->extensions = data;
    else
        this->extensions = NULL;
}

void tlsExtensionSignatureAlgorithmsParse(TlsExtensionSignatureAlgorithms *this, void *data, uint32_t size) {
    uint16_t algorithmsSize = SWAP_ENDIAN_16(*(uint16_t *)data);
    this->algorithmCount = algorithmsSize / sizeof(TlsSignatureAlgorithm);
    data += sizeof(uint16_t);
    this->algorithms = data;
    data += algorithmsSize;
}

void tlsExtensionSupportedVersionsClientParse(TlsExtensionSupportedVersionsClient *this, void *data, uint32_t size) {
    uint8_t versionsSize = *(uint8_t *)data;
    this->versionCount = versionsSize / sizeof(TlsVersion);
    data += sizeof(uint8_t);
    this->versions = data;
    data += versionsSize;
}

void tlsExtensionSupportedVersionsServerParse(TlsExtensionSupportedVersionsServer *this, void *data, uint32_t size) {
    this->version = *(TlsVersion *)data;
    data += sizeof(TlsVersion);
}
