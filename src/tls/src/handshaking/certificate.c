#include <tls/private.h>

#include <tls/handshakes.h>

#include <stdio.h>

bool tlsConnectionHandleHandshakeCertificate(TlsConnection *this, void *data, uint32_t size) {
    TlsHandshakeCertificates certificates;
    tlsHandshakeCertificatesParse(&certificates, data, size);

    uint32_t count = 0;
    void *thisCertificate = certificates.firstCertificate;

    while (thisCertificate) {
        TlsHandshakeCertificate certificate;
        thisCertificate = tlsHandshakeCertificateParse(&certificates, thisCertificate, &certificate);

        printf("\tCertificate: ");
        for (uint32_t a = 0; a < certificate.size; a++) {
            printf("%02X", certificate.data[a]);
        }
        printf("\n");

        count++;
    }

    return true;
}