#pragma once

#include <stdlib.h>
#include <stdbool.h>

bool socketReadCallback(void *socket, void *data, size_t size);
bool socketWriteCallback(void *socket, void *data, size_t size);
