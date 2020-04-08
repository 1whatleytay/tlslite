#include <tls/names.h>

const char *tlsContentTypeName(TlsContentType this) {
    switch (this) {
        case TlsContentTypeChangeCipherSpec: return "ChangeCipherSpec";
        case TlsContentTypeAlert: return "Alert";
        case TlsContentTypeHandshake: return "Handshake";
        case TlsContentTypeApplicationData: return "ApplicationData";
        default: return "Unknown";
    }
}

const char *tlsHandshakeTypeName(TlsHandshakeType this) {
    switch (this) {
        case TlsHandshakeTypeHelloRequest: return "HelloRequest";
        case TlsHandshakeTypeClientHello: return "ClientHello";
        case TlsHandshakeTypeServerHello: return "ServerHello";
        case TlsHandshakeTypeCertificate: return "Certificate";
        case TlsHandshakeTypeServerKeyExchange: return "ServerKeyExchange";
        case TlsHandshakeTypeCertificateRequest: return "CertificateRequest";
        case TlsHandshakeTypeServerHelloDone: return "ServerHelloDone";
        case TlsHandshakeTypeCertificateVerify: return "CertificateVerify";
        case TlsHandshakeTypeClientKeyExchange: return "ClientKeyExchange";
        case TlsHandshakeTypeFinished: return "Finished";
        default: return "Unknown";
    }
}

const char *tlsAlertLevelName(TlsAlertLevel this) {
    switch (this) {
        case TlsAlertLevelWarning: return "Warning";
        case TlsAlertLevelFatal: return "Fatal";
        default: return "Unknown";
    }
}

const char *tlsAlertDescriptionName(TlsAlertDescription this) {
    switch (this) {
        case TlsAlertDescriptionCloseNotification: return "CloseNotification";
        case TlsAlertDescriptionUnexpectedMessage: return "UnexpectedMessage";
        case TlsAlertDescriptionBadRecordMac: return "BadRecordMac";
        case TlsAlertDescriptionDecryptionFailed: return "DecryptionFailed";
        case TlsAlertDescriptionRecordOverflow: return "RecordOverflow";
        case TlsAlertDescriptionDecompressionFailure: return "DecompressionFailure";
        case TlsAlertDescriptionHandshakeFailure: return "HandshakeFailure";
        case TlsAlertDescriptionNoCertificate: return "NoCertificate";
        case TlsAlertDescriptionBadCertificate: return "BadCertificate";
        case TlsAlertDescriptionUnsupportedCertificate: return "UnsupportedCertificate";
        case TlsAlertDescriptionCertificateRevoked: return "CertificateRevoked";
        case TlsAlertDescriptionCertificateExpired: return "CertificateExpired";
        case TlsAlertDescriptionCertificateUnknown: return "CertificateUnknown";
        case TlsAlertDescriptionIllegalParameter: return "IllegalParameter";
        case TlsAlertDescriptionUnknownCa: return "UnknownCa";
        case TlsAlertDescriptionAccessDenied: return "AccessDenied";
        case TlsAlertDescriptionDecodeError: return "DecodeError";
        case TlsAlertDescriptionDecryptError: return "DecryptError";
        case TlsAlertDescriptionExportRestriction: return "ExportRestriction";
        case TlsAlertDescriptionProtocolVersion: return "ProtocolVersion";
        case TlsAlertDescriptionInsufficientSecurity: return "InsufficientSecurity";
        case TlsAlertDescriptionInternalError: return "InternalError";
        case TlsAlertDescriptionUserCanceled: return "UserCanceled";
        case TlsAlertDescriptionNoRenegotiation: return "NoRenegotiation";
        case TlsAlertDescriptionUnsupportedExtension: return "UnsupportedExtension";
        default: return "Unknown";
    }
}

const char *tlsCipherSuiteName(TlsCipherSuite this) {
    switch (this) {
        case TlsCipherSuiteNoCipher: return "NoCipher";
        case TlsCipherSuiteRsaWithMD5: return "RsaWithMD5";
        case TlsCipherSuiteRsaWithSha: return "RsaWithSha";
        case TlsCipherSuiteRsaWithSha256: return "RsaWithSha256";
        case TlsCipherSuiteRsaWithRc4128MD5: return "RsaWithRc4128MD5";
        case TlsCipherSuiteRsaWithRc4128Sha: return "RsaWithRc4128Sha";
        case TlsCipherSuiteRsaWith3desEdeCbcSha: return "RsaWith3desEdeCbcSha";
        case TlsCipherSuiteRsaWithAes128CbcSha: return "RsaWithAes128CbcSha";
        case TlsCipherSuiteRsaWithAes256CbcSha: return "RsaWithAes256CbcSha";
        case TlsCipherSuiteRsaWithAes128CbcSha256: return "RsaWithAes128CbcSha256";
        case TlsCipherSuiteRsaWithAes256CbcSha256: return "RsaWithAes256CbcSha256";
        case TlsCipherSuiteEcdheEcdsaWithAes128GcmSha256: return "EcdheEcdsaWithAes128GcmSha256";
        case TlsCipherSuiteEcdheRsaWithAes128GcmSha256: return "EcdheRsaWithAes128GcmSha256";
        case TlsCipherSuiteEcdheEcdsaWithAes256GcmSha384: return "EcdheEcdsaWithAes256GcmSha384";
        case TlsCipherSuiteEcdheRsaWithAes256GcmSha384: return "EcdheRsaWithAes256GcmSha384";
        case TlsCipherSuitePskWithAes256Ccm8: return "PskWithAes256Ccm8";
        case TlsCipherSuitePskWithAes128Ccm8: return "PskWithAes128Ccm8";
        case TlsCipherSuiteEcdheRsaWithAes128CbcSha: return "EcdheRsaWithAes128CbcSha";
        case TlsCipherSuiteEcdheRsaWithAes256CbcSha: return "EcdheRsaWithAes256CbcSha";
        case TlsCipherSuiteRsaWithAes128GcmSha256: return "RsaWithAes128GcmSha256";
        case TlsCipherSuiteRsaWithAes256GcmSha384: return "RsaWithAes256GcmSha384";
        default: return "Unknown";
    }
}

const char *tlsCompressionMethodName(TlsCompressionMethod this) {
    switch (this) {
        case TlsCompressionMethodNone: return "None";
        default: return "Unknown";
    }
}

const char *tlsExtensionTypeName(TlsExtensionType this) {
    switch (this) {
        case TlsExtensionTypeServerName: return "ServerName";
        case TlsExtensionTypeMaxFragmentLength: return "MaxFragmentLength";
        case TlsExtensionTypeStatusRequest: return "StatusRequest";
        case TlsExtensionTypeSupportedGroups: return "SupportedGroups";
        case TlsExtensionTypeSignatureAlgorithms: return "SignatureAlgorithms";
        case TlsExtensionTypeUseSrtp: return "UseSrtp";
        case TlsExtensionTypeHeartbeat: return "Heartbeat";
        case TlsExtensionTypeProtocolNames: return "ProtocolNames";
        case TlsExtensionTypeSignedCertificateTimestamp: return "SignedCertificateTimestamp";
        case TlsExtensionTypeClientCertificateType: return "ClientCertificateType";
        case TlsExtensionTypeServerCertificateType: return "ServerCertificateType";
        case TlsExtensionTypePadding: return "Padding";
        case TlsExtensionTypePreSharedKey: return "PreSharedKey";
        case TlsExtensionTypeEarlyData: return "EarlyData";
        case TlsExtensionTypeSupportedVersions: return "SupportedVersions";
        case TlsExtensionTypeCookie: return "Cookie";
        case TlsExtensionTypePskKeyExchange_Modes: return "PskKeyExchange_Modes";
        case TlsExtensionTypeCertificateAuthorities: return "CertificateAuthorities";
        case TlsExtensionTypeOidFilters: return "OidFilters";
        case TlsExtensionTypePostHandshakeAuth: return "PostHandshakeAuth";
        case TlsExtensionTypeSignatureAlgorithmsCert: return "SignatureAlgorithmsCert";
        case TlsExtensionTypeKeyShare: return "KeyShare";
        default: return "Unknown";
    }
}

const char *tlsSupportedGroupName(TlsSupportedGroup this) {
    switch (this) {
        case TlsSupportedGroupSecp256r1: return "Secp256r1";
        case TlsSupportedGroupSecp384r1: return "Secp384r1";
        case TlsSupportedGroupSecp521r1: return "Secp521r1";
        case TlsSupportedGroupX25519: return "X25519";
        case TlsSupportedGroupX448: return "X448";
        case TlsSupportedGroupFfdhe2048: return "Ffdhe2048";
        case TlsSupportedGroupFfdhe3072: return "Ffdhe3072";
        case TlsSupportedGroupFfdhe4096: return "Ffdhe4096";
        case TlsSupportedGroupFfdhe6144: return "Ffdhe6144";
        case TlsSupportedGroupFfdhe8192: return "Ffdhe8192";
        default: return "Unknown";
    }
}

const char *tlsSignatureAlgorithmName(TlsSignatureAlgorithm this) {
    switch (this) {
        case TlsSignatureAlgorithmRsaPkcs1Sha256: return "RsaPkcs1Sha256";
        case TlsSignatureAlgorithmRsaPkcs1Sha384: return "RsaPkcs1Sha384";
        case TlsSignatureAlgorithmRsaPkcs1Sha512: return "RsaPkcs1Sha512";
        case TlsSignatureAlgorithmEcdsaSecp256r1Sha256: return "EcdsaSecp256r1Sha256";
        case TlsSignatureAlgorithmEcdsaSecp384r1Sha384: return "EcdsaSecp384r1Sha384";
        case TlsSignatureAlgorithmEcdsaSecp521r1Sha512: return "EcdsaSecp521r1Sha512";
        case TlsSignatureAlgorithmRsaPssRsaeSha256: return "RsaPssRsaeSha256";
        case TlsSignatureAlgorithmRsaPssRsaeSha384: return "RsaPssRsaeSha384";
        case TlsSignatureAlgorithmRsaPssRsaeSha512: return "RsaPssRsaeSha512";
        case TlsSignatureAlgorithmEd25519: return "Ed25519";
        case TlsSignatureAlgorithmEd448: return "Ed448";
        case TlsSignatureAlgorithmRsaPssPssSha256: return "RsaPssPssSha256";
        case TlsSignatureAlgorithmRsaPssPssSha384: return "RsaPssPssSha384";
        case TlsSignatureAlgorithmRsaPssPssSha512: return "RsaPssPssSha512";
        case TlsSignatureAlgorithmRsaPkcs1Sha1: return "RsaPkcs1Sha1";
        case TlsSignatureAlgorithmEcdsaSha1: return "EcdsaSha1";
        default: return "Unknown";
    }
}
