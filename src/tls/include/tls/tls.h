#pragma once

#include <stdint.h>

#define SWAP_ENDIAN_16(a) (((a) >> 8u) | ((a) << 8u) & 0xFFFF)

typedef enum : uint8_t {
    TlsContentTypeChangeCipherSpec = 20,
    TlsContentTypeAlert = 21,
    TlsContentTypeHandshake = 22,
    TlsContentTypeApplicationData = 23,
} TlsContentType;

typedef enum : uint8_t {
    TlsHandshakeTypeHelloRequest = 0,
    TlsHandshakeTypeClientHello = 1,
    TlsHandshakeTypeServerHello = 2,
    TlsHandshakeTypeCertificate = 11,
    TlsHandshakeTypeServerKeyExchange = 12,
    TlsHandshakeTypeCertificateRequest = 13,
    TlsHandshakeTypeServerHelloDone = 14,
    TlsHandshakeTypeCertificateVerify = 15,
    TlsHandshakeTypeClientKeyExchange = 16,
    TlsHandshakeTypeFinished = 20,
} TlsHandshakeType;

typedef enum : uint8_t {
    TlsAlertLevelWarning = 1,
    TlsAlertLevelFatal = 2,
} TlsAlertLevel;

typedef enum : uint8_t {
    TlsAlertDescriptionCloseNotification = 0,
    TlsAlertDescriptionUnexpectedMessage = 10,
    TlsAlertDescriptionBadRecordMac = 20,
    TlsAlertDescriptionDecryptionFailed = 21,
    TlsAlertDescriptionRecordOverflow = 22,
    TlsAlertDescriptionDecompressionFailure = 30,
    TlsAlertDescriptionHandshakeFailure = 40,
    TlsAlertDescriptionNoCertificate = 41,
    TlsAlertDescriptionBadCertificate = 42,
    TlsAlertDescriptionUnsupportedCertificate = 43,
    TlsAlertDescriptionCertificateRevoked = 44,
    TlsAlertDescriptionCertificateExpired = 45,
    TlsAlertDescriptionCertificateUnknown = 46,
    TlsAlertDescriptionIllegalParameter = 47,
    TlsAlertDescriptionUnknownCa = 48,
    TlsAlertDescriptionAccessDenied = 49,
    TlsAlertDescriptionDecodeError = 50,
    TlsAlertDescriptionDecryptError = 51,
    TlsAlertDescriptionExportRestriction = 60,
    TlsAlertDescriptionProtocolVersion = 70,
    TlsAlertDescriptionInsufficientSecurity = 71,
    TlsAlertDescriptionInternalError = 80,
    TlsAlertDescriptionUserCanceled = 90,
    TlsAlertDescriptionNoRenegotiation = 100,
    TlsAlertDescriptionUnsupportedExtension = 110,
} TlsAlertDescription;

typedef enum : uint16_t {
    TlsCipherSuiteNoCipher = 0x0000,
    TlsCipherSuiteRsaWithMD5 = 0x0100,
    TlsCipherSuiteRsaWithSha = 0x0200,
    TlsCipherSuiteRsaWithSha256 = 0x3B00,
    TlsCipherSuiteRsaWithRc4128MD5 = 0x0400,
    TlsCipherSuiteRsaWithRc4128Sha = 0x0500,
    TlsCipherSuiteRsaWith3desEdeCbcSha = 0x0A00,
    TlsCipherSuiteRsaWithAes128CbcSha = 0x2F00,
    TlsCipherSuiteRsaWithAes256CbcSha = 0x3500,
    TlsCipherSuiteRsaWithAes128CbcSha256 = 0x3C00,
    TlsCipherSuiteRsaWithAes256CbcSha256 = 0x3D00,
    TlsCipherSuiteEcdheEcdsaWithAes128GcmSha256 = 0x2BC0,
    TlsCipherSuiteEcdheRsaWithAes128GcmSha256 = 0x2FC0,
    TlsCipherSuiteEcdheEcdsaWithAes256GcmSha384 = 0x2CC0,
    TlsCipherSuiteEcdheRsaWithAes256GcmSha384 = 0x30C0,
    TlsCipherSuitePskWithAes256Ccm8 = 0xA9CC,
    TlsCipherSuitePskWithAes128Ccm8 = 0xA8CC,
    TlsCipherSuiteEcdheRsaWithAes128CbcSha = 0x13C0,
    TlsCipherSuiteEcdheRsaWithAes256CbcSha = 0x14C0,
    TlsCipherSuiteRsaWithAes128GcmSha256 = 0x9C00,
    TlsCipherSuiteRsaWithAes256GcmSha384 = 0x9D00,
} TlsCipherSuite;

typedef enum : uint16_t {
    TlsExtensionTypeServerName = 0x0000,
    TlsExtensionTypeMaxFragmentLength = 0x0100,
    TlsExtensionTypeStatusRequest = 0x0500,
    TlsExtensionTypeSupportedGroups = 0x0A00,
    TlsExtensionTypeSignatureAlgorithms = 0x0D00,
    TlsExtensionTypeUseSrtp = 0x0E00,
    TlsExtensionTypeHeartbeat = 0x0F00,
    TlsExtensionTypeProtocolNames = 0x1000, // TlsExtensionTypeApplicationLayerProtocolNegotiation
    TlsExtensionTypeSignedCertificateTimestamp = 0x1200,
    TlsExtensionTypeClientCertificateType = 0x1300,
    TlsExtensionTypeServerCertificateType = 0x1400,
    TlsExtensionTypePadding = 0x1500,
    TlsExtensionTypePreSharedKey = 0x2900,
    TlsExtensionTypeEarlyData = 0x2A00,
    TlsExtensionTypeSupportedVersions = 0x2B00,
    TlsExtensionTypeCookie = 0x2C00,
    TlsExtensionTypePskKeyExchange_Modes = 0x2D00,
    TlsExtensionTypeCertificateAuthorities = 0x2F00,
    TlsExtensionTypeOidFilters = 0x3000,
    TlsExtensionTypePostHandshakeAuth = 0x3100,
    TlsExtensionTypeSignatureAlgorithmsCert = 0x3200,
    TlsExtensionTypeKeyShare = 0x3300,
} TlsExtensionType;

typedef enum : uint16_t {
    TlsSupportedGroupSecp256r1 = 0x1700,
    TlsSupportedGroupSecp384r1 = 0x1800,
    TlsSupportedGroupSecp521r1 = 0x1900,
    TlsSupportedGroupX25519 = 0x1D00,
    TlsSupportedGroupX448 = 0x1E00,
    TlsSupportedGroupFfdhe2048 = 0x0001,
    TlsSupportedGroupFfdhe3072 = 0x0101,
    TlsSupportedGroupFfdhe4096 = 0x0201,
    TlsSupportedGroupFfdhe6144 = 0x0301,
    TlsSupportedGroupFfdhe8192 = 0x0401,
} TlsSupportedGroup;

typedef enum : uint16_t {
    TlsSignatureAlgorithmRsaPkcs1Sha256 = 0x0104,
    TlsSignatureAlgorithmRsaPkcs1Sha384 = 0x0105,
    TlsSignatureAlgorithmRsaPkcs1Sha512 = 0x0106,
    TlsSignatureAlgorithmEcdsaSecp256r1Sha256 = 0x0304,
    TlsSignatureAlgorithmEcdsaSecp384r1Sha384 = 0x0305,
    TlsSignatureAlgorithmEcdsaSecp521r1Sha512 = 0x0306,
    TlsSignatureAlgorithmRsaPssRsaeSha256 = 0x0408,
    TlsSignatureAlgorithmRsaPssRsaeSha384 = 0x0508,
    TlsSignatureAlgorithmRsaPssRsaeSha512 = 0x0608,
    TlsSignatureAlgorithmEd25519 = 0x0708,
    TlsSignatureAlgorithmEd448 = 0x0808,
    TlsSignatureAlgorithmRsaPssPssSha256 = 0x0908,
    TlsSignatureAlgorithmRsaPssPssSha384 = 0x0a08,
    TlsSignatureAlgorithmRsaPssPssSha512 = 0x0b08,
    TlsSignatureAlgorithmRsaPkcs1Sha1 = 0x0102,
    TlsSignatureAlgorithmEcdsaSha1 = 0x0302,
} TlsSignatureAlgorithm;

typedef enum : uint8_t {
    TlsCompressionMethodNone = 0,
} TlsCompressionMethod;

typedef uint8_t TlsUint24[3];

typedef struct {
    uint8_t major;
    uint8_t minor;
} TlsVersion;

typedef char TlsRandom[32];

typedef struct {
    TlsContentType type;
    TlsVersion version;
    uint16_t length;
} TlsPlaintextHeader;

typedef struct {
    TlsHandshakeType type;
    uint32_t length;
} TlsHandshakeHeader;

typedef struct {
    TlsExtensionType type;
    uint16_t length;
} TlsExtensionHeader;

typedef struct {
    TlsAlertLevel level;
    TlsAlertDescription description;
} TlsAlert;

// Special Parse Functions for Structures with Endian Issues
void *tlsPlaintextHeaderParse(TlsPlaintextHeader *this, void *data);
uint32_t tlsPlaintextHeaderGetSize();
void tlsPlaintextHeaderSerialize(TlsPlaintextHeader *this, void *data);

void *tlsHandshakeHeaderParse(TlsHandshakeHeader *this, void *data);
uint32_t tlsHandshakeHeaderGetSize();
void tlsHandshakeHeaderSerialize(TlsHandshakeHeader *this, void *data);

void *tlsExtensionHeaderParse(TlsExtensionHeader *this, void *data);
uint32_t tlsExtensionHeaderGetSize();
void tlsExtensionHeaderSerialize(TlsExtensionHeader *this, void *data);

void tlsRandomFill(TlsRandom random);
void tlsRandomSetVersion(TlsRandom random, TlsVersion version);

void tlsUint24Pack(TlsUint24 this, uint32_t value);
uint32_t tlsUint24Unpack(const TlsUint24 this);
