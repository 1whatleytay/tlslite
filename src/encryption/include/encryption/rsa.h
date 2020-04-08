#pragma once

#include <stdint.h>

typedef uint32_t RsaKey[8]; // 256 bit

typedef struct {
    RsaKey public;
    RsaKey private;
} RsaKeys;

void rsaKeysInit(RsaKeys *this);
