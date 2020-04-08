#include <encryption/rsa.h>

void rsaKeysInit(RsaKeys *this) {
    // too lazy to use a cspring, might make a random.h so it will be easy to override later
    const uint32_t p = 7;
    const uint32_t q = 13;

    uint32_t n = p * q;
    uint32_t t = (p - 1) * (q - 1);
}