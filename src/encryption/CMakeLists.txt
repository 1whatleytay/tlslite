add_library(encryption STATIC
    include/encryption/random.h
    include/encryption/rsa.h
    include/encryption/sha.h

    src/random.c
    src/rsa.c
    src/sha.c)

target_include_directories(encryption PUBLIC include)
