#include <encryption/random.h>

#include <stdlib.h>

void randomInit(uint8_t *data, uint32_t size) {
    for (uint32_t a = 0; a < size; a++) {
        // supposed to be a cspring but I can't be bothered... use Windows rand_s or POSIX random() in future?

        data[a] = (uint8_t)rand();
    }
}