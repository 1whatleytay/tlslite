#pragma once

#include <tls/tls.h>

#include <stdint.h>

typedef struct {
    uint8_t nameType; // almost always the same
    uint16_t nameLength;
    char *name;
} TlsExtensionServerName;

typedef struct {
    uint16_t serverNameSize;
    void *firstServerName;
} TlsExtensionServerNames;

typedef struct {
    uint16_t supportedGroupCount;
    TlsSupportedGroup *supportedGroups;
} TlsExtensionSupportedGroups;

typedef struct {
    uint8_t protocolSize;
    char *protocol;
} TlsExtensionProtocolName;

typedef struct {
    uint16_t protocolSize;
    void *firstProtocol;
} TlsExtensionProtocolNames;

typedef struct {
    uint8_t statusType;
    uint16_t responderIdSize;
    void *firstResponderId;
    uint16_t extensionsSize;
    void *extensions;
} TlsExtensionStatusRequest;

typedef struct {
    uint16_t algorithmCount;
    TlsSignatureAlgorithm *algorithms;
} TlsExtensionSignatureAlgorithms;

typedef struct {
    uint8_t versionCount;
    TlsVersion *versions;
} TlsExtensionSupportedVersionsClient;

typedef struct {
    TlsVersion version;
} TlsExtensionSupportedVersionsServer;

typedef struct {
    TlsExtensionHeader header;
    void *data;
} TlsExtensionContainer;

void tlsExtensionServerNamesParse(TlsExtensionServerNames *this, void *data, uint32_t size);
void *tlsExtensionServerNameParse(TlsExtensionServerNames *this, void *data, TlsExtensionServerName *name);

void tlsExtensionSupportedGroupsParse(TlsExtensionSupportedGroups *this, void *data, uint32_t size);

void tlsExtensionProtocolNamesParse(TlsExtensionProtocolNames *this, void *data, uint32_t size);
void *tlsExtensionProtocolNameParse(TlsExtensionProtocolNames *this, void *data, TlsExtensionProtocolName *name);

void tlsExtensionStatusRequestParse(TlsExtensionStatusRequest *this, void *data, uint32_t size);

void tlsExtensionSignatureAlgorithmsParse(TlsExtensionSignatureAlgorithms *this, void *data, uint32_t size);

void tlsExtensionSupportedVersionsClientParse(TlsExtensionSupportedVersionsClient *this, void *data, uint32_t size);

uint32_t tlsExtensionsSerializeGetSize(TlsExtensionContainer *containers, uint32_t count);
void tlsExtensionsSerialize(TlsExtensionContainer *containers, uint32_t count);
