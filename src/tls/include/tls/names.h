#pragma once

#include <tls/tls.h>

const char *tlsContentTypeName(TlsContentType this);
const char *tlsHandshakeTypeName(TlsHandshakeType this);
const char *tlsAlertLevelName(TlsAlertLevel this);
const char *tlsAlertDescriptionName(TlsAlertDescription this);
const char *tlsCipherSuiteName(TlsCipherSuite this);
const char *tlsCompressionMethodName(TlsCompressionMethod this);
const char *tlsExtensionTypeName(TlsExtensionType this);
const char *tlsSupportedGroupName(TlsSupportedGroup this);
const char *tlsSignatureAlgorithmName(TlsSignatureAlgorithm this);
