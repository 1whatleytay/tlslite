#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include <tls/tls.h>

typedef bool (* TlsConnectionIoCallback)(void *userData, void *data, size_t size);

typedef enum {
    TlsErrorNone,
    TlsErrorCannotConnect,
    TlsErrorCannotStart,
    TlsErrorCannotHost,
    TlsErrorCannotListen,
    TlsErrorFailedHandshake,
    TlsErrorFailedAlert,
    TlsErrorConnectionClosed,
} TlsError;

typedef enum {
    TlsTypeClosed,
    TlsTypeServer,
    TlsTypeClient,
} TlsType;

typedef struct {
    TlsType type;

    // Meta
    TlsVersion version;
    uint32_t supportedCipherSuiteCount;
    TlsCipherSuite *supportedCipherSuites;
    uint32_t supportedCompressionMethodCount;
    TlsCompressionMethod *supportedCompressionMethods;

    // IO
    void *userData;
    TlsConnectionIoCallback read;
    TlsConnectionIoCallback write;
} TlsConnection;

TlsError tlsConnectionInit(TlsConnection *this, TlsType type,
    TlsConnectionIoCallback read, TlsConnectionIoCallback write, void *userData);
TlsError tlsConnectionStart(TlsConnection *this);
void tlsConnectionClose(TlsConnection *this);
