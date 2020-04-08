#pragma once

#include <tls/connection.h>

// Sending
bool tlsConnectionSendPlaintextHeader(TlsConnection *this, TlsContentType type, uint16_t size);
bool tlsConnectionSendHandshakeHeader(TlsConnection *this, TlsHandshakeType type, uint32_t size);

// Handshaking
bool tlsConnectionInitHandshake(TlsConnection *this);
bool tlsConnectionHandleHandshakeClientHello(TlsConnection *this, void *data, uint32_t size);
bool tlsConnectionHandleHandshakeServerHello(TlsConnection *this, void *data, uint32_t size);
bool tlsConnectionHandleHandshakeCertificate(TlsConnection *this, void *data, uint32_t size);
bool tlsConnectionHandleHandshakeServerHelloDone(TlsConnection *this, void *data, uint32_t size);