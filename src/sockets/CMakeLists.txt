add_library(sockets STATIC
    include/sockets/sockets.h
    include/sockets/callbacks.h

    src/sockets.c
    src/callbacks.c)

target_include_directories(sockets PUBLIC include)
