add_library(tls STATIC
    include/tls/tls.h
    include/tls/names.h
    include/tls/handshakes.h
    include/tls/extensions.h
    include/tls/connection.h
    include/tls/private.h

    src/tls.c
    src/names.c
    src/handshakes.c
    src/extensions.c
    src/connection.c

    src/handshaking/init.c
    src/handshaking/client_hello.c
    src/handshaking/server_hello.c
    src/handshaking/certificate.c
    src/handshaking/server_hello_done.c)

target_include_directories(tls PUBLIC include)
target_link_libraries(tls PUBLIC encryption)
