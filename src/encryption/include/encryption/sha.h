#pragma once

#include <stdint.h>

typedef uint32_t Sha256Hash[8];

void sha256HashInit(Sha256Hash this, const void *data, uint64_t size);
