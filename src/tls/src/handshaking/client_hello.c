#include <tls/private.h>

#include <tls/tls.h>
#include <tls/names.h>
#include <tls/extensions.h>
#include <tls/handshakes.h>

#include <stdio.h>
#include <assert.h>

static bool tlsConnectionHandleHandshakeClientHelloExtensions(TlsConnection *this, void *data, uint16_t size) {
    void *start = data;

    while (((uintptr_t)data - (uintptr_t)start) < size) {
        TlsExtensionHeader header;
        data = tlsExtensionHeaderParse(&header, data);

        printf("\tExtension: %s\n", tlsExtensionTypeName(header.type));

        void *extensionData = data;
        uint32_t extensionSize = header.length;

        switch (header.type) {
            case TlsExtensionTypeServerName: {
                TlsExtensionServerNames serverNames;
                tlsExtensionServerNamesParse(&serverNames, extensionData, extensionSize);

                void *thisName = serverNames.firstServerName;

                while (thisName) {
                    TlsExtensionServerName name;
                    thisName = tlsExtensionServerNameParse(&serverNames, thisName, &name);

                    printf("\t\tName: %.*s\n", (uint32_t)name.nameLength, name.name);
                }

                break;
            }

            case TlsExtensionTypeSupportedGroups: {
                TlsExtensionSupportedGroups groups;
                tlsExtensionSupportedGroupsParse(&groups, extensionData, extensionSize);

                for (uint32_t a = 0; a < groups.supportedGroupCount; a++) {
                    printf("\t\tGroup: %s\n", tlsSupportedGroupName(groups.supportedGroups[a]));
                }

                break;
            }

            case TlsExtensionTypeProtocolNames: {
                TlsExtensionProtocolNames names;
                tlsExtensionProtocolNamesParse(&names, extensionData, extensionSize);

                void *thisProtocol = names.firstProtocol;
                while (thisProtocol) {
                    TlsExtensionProtocolName name;
                    thisProtocol = tlsExtensionProtocolNameParse(&names, thisProtocol, &name);

                    printf("\t\tProtocol: %.*s\n", (uint32_t)name.protocolSize, name.protocol);
                }

                break;
            }

            case TlsExtensionTypeStatusRequest: {
                TlsExtensionStatusRequest statusRequest;
                tlsExtensionStatusRequestParse(&statusRequest, extensionData, extensionSize);

                printf("\t\tResponder ID Size: %i\n", statusRequest.responderIdSize);
                printf("\t\tExtensions Size: %i\n", statusRequest.extensionsSize);

                break;
            }

            case TlsExtensionTypeSignatureAlgorithms: {
                TlsExtensionSignatureAlgorithms algorithms;
                tlsExtensionSignatureAlgorithmsParse(&algorithms, extensionData, extensionSize);

                for (uint32_t a = 0; a < algorithms.algorithmCount; a++) {
                    printf("\t\tAlgorithm: %s\n", tlsSignatureAlgorithmName(algorithms.algorithms[a]));
                }

                break;
            }

            case TlsExtensionTypeSupportedVersions: {
                TlsExtensionSupportedVersionsClient versions;
                tlsExtensionSupportedVersionsClientParse(&versions, extensionData, extensionSize);

                for (uint32_t a = 0; a < versions.versionCount; a++) {
                    printf("\t\tVersion: %i.%i\n", versions.versions[a].major, versions.versions[a].minor);
                }

                break;
            }

            default:
                break;
        }

        data += header.length;
    }

    return true;
}

bool tlsConnectionHandleHandshakeClientHello(TlsConnection *this, void *data, uint32_t size) {
    assert(this->type == TlsTypeServer);

    TlsHandshakeClientHello clientHello;
    tlsHandshakeClientHelloParse(&clientHello, data, size);

    printf("\tVersion: %i.%i\n", clientHello.version->major, clientHello.version->minor);

    printf("\tCipher Suites:\n");
    for (uint32_t a = 0; a < clientHello.cipherSuiteCount; a++) {
        printf("\t\tSuite: %s\n", tlsCipherSuiteName(clientHello.cipherSuites[a]));
    }

    if (clientHello.extensions) {
        tlsConnectionHandleHandshakeClientHelloExtensions(this, clientHello.extensions, clientHello.extensionsSize);
    }

    // Send Server Hello
    TlsRandom random;
    tlsRandomFill(random);
    tlsRandomSetVersion(random, *clientHello.version);

    TlsHandshakeServerHello serverHello;
    serverHello.version = &this->version;
    serverHello.random = &random;
    serverHello.sessionIdSize = clientHello.sessionIdSize;
    serverHello.sessionId = clientHello.sessionId;
    serverHello.cipherSuite = TlsCipherSuiteRsaWithAes128CbcSha;
    serverHello.compressionMethod = TlsCompressionMethodNone;
    serverHello.extensionsSize = 0;
    serverHello.extensions = NULL;

    uint32_t serverHelloSize = tlsHandshakeServerHelloSerializeGetSize(&serverHello);
    uint8_t serverHelloData[serverHelloSize];
    tlsHandshakeServerHelloSerialize(&serverHello, serverHelloData);

    if (!tlsConnectionSendPlaintextHeader(this, TlsContentTypeHandshake,
        serverHelloSize + tlsHandshakeHeaderGetSize()))
        assert(false);

    if (!tlsConnectionSendHandshakeHeader(this, TlsHandshakeTypeServerHello, serverHelloSize))
        assert(false);

    if (!this->write(this->userData, serverHelloData, serverHelloSize))
        assert(false);

    // Send Certificates
    uint32_t certificatesSize = tlsHandshakeCertificatesSerializeGetSize(NULL, 0);
    uint8_t certificatesData[certificatesSize];
    tlsHandshakeCertificatesSerialize(NULL, 0, certificatesData);

    if (!tlsConnectionSendPlaintextHeader(this, TlsContentTypeHandshake,
        tlsHandshakeHeaderGetSize() + certificatesSize))
        assert(false);

    if (!tlsConnectionSendHandshakeHeader(this, TlsHandshakeTypeCertificate, certificatesSize))
        assert(false);

    if (!this->write(this->userData, certificatesData, certificatesSize))
        assert(false);

    if (!tlsConnectionSendPlaintextHeader(this, TlsContentTypeHandshake, tlsHandshakeHeaderGetSize()))
        assert(false);

    if (!tlsConnectionSendHandshakeHeader(this, TlsHandshakeTypeServerHelloDone, 0))
        assert(false);

    return true;
}