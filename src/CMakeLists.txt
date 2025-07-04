
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/jansson-2.14/src
    ${CMAKE_CURRENT_BINARY_DIR}
)

set(ASSEMBLY_OBJECTS)

if(HAVE_AVX1)
    set(ASSEMBLY_FILE "${CMAKE_CURRENT_SOURCE_DIR}/sha256_code_release/sha256_avx1.asm")
    set(ASSEMBLY_OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/sha256_avx.o")
    add_custom_command(
        OUTPUT ${ASSEMBLY_OUTPUT}
        COMMAND yasm -f elf64 -X gnu -g dwarf2 -D LINUX -o ${ASSEMBLY_OUTPUT} ${ASSEMBLY_FILE}
        DEPENDS ${ASSEMBLY_FILE}
        COMMENT "Building AVX SHA256 implementation"
    )
    list(APPEND ASSEMBLY_OBJECTS ${ASSEMBLY_OUTPUT})
    add_definitions(-DUSE_AVX1)
elseif(HAVE_AVX2)
    set(ASSEMBLY_FILE "${CMAKE_CURRENT_SOURCE_DIR}/sha256_code_release/sha256_avx2_rorx2.asm")
    set(ASSEMBLY_OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/sha256_avx2.o")
    add_custom_command(
        OUTPUT ${ASSEMBLY_OUTPUT}
        COMMAND yasm -f elf64 -X gnu -g dwarf2 -D LINUX -o ${ASSEMBLY_OUTPUT} ${ASSEMBLY_FILE}
        DEPENDS ${ASSEMBLY_FILE}
        COMMENT "Building AVX2 SHA256 implementation"
    )
    list(APPEND ASSEMBLY_OBJECTS ${ASSEMBLY_OUTPUT})
    add_definitions(-DUSE_AVX2)
elseif(HAVE_SSE4)
    set(ASSEMBLY_FILE "${CMAKE_CURRENT_SOURCE_DIR}/sha256_code_release/sha256_sse4.asm")
    set(ASSEMBLY_OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/sha256_sse4.o")
    add_custom_command(
        OUTPUT ${ASSEMBLY_OUTPUT}
        COMMAND yasm -f elf64 -X gnu -g dwarf2 -D LINUX -o ${ASSEMBLY_OUTPUT} ${ASSEMBLY_FILE}
        DEPENDS ${ASSEMBLY_FILE}
        COMMENT "Building SSE4 SHA256 implementation"
    )
    list(APPEND ASSEMBLY_OBJECTS ${ASSEMBLY_OUTPUT})
    add_definitions(-DUSE_SSE4)
endif()

if(ASSEMBLY_OBJECTS)
    add_custom_target(sha256_asm ALL DEPENDS ${ASSEMBLY_OBJECTS})
endif()

# Main library
add_library(ckpool_lib STATIC
    libckpool.c
    sha2.c
    ${ASSEMBLY_OBJECTS}
)

if(ASSEMBLY_OBJECTS)
    add_dependencies(ckpool_lib sha256_asm)
endif()

# Executables
add_executable(ckpool
    ckpool.c
    generator.c
    bitcoin.c
    stratifier.c
    connector.c
)

target_link_libraries(ckpool
    ckpool_lib 
    ${JANSSON_LIB} 
    ${PTHREAD_LIB} 
    ${M_LIB} 
    ${RT_LIB} 
    ${ZMQ_LIB}
)

#add_executable(ckpmsg ckpmsg.c)
#target_link_libraries(ckpmsg ckpool_lib ${M_LIB})

# Installation
#install(TARGETS ckpool ckpmsg
#    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
#)
install(TARGETS ckpool
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Post-install hooks
install(CODE "
    # Set capabilities for ckpool
    execute_process(COMMAND setcap CAP_NET_BIND_SERVICE=+eip \$ENV{DESTDIR}${CMAKE_INSTALL_FULL_BINDIR}/ckpool)
    
    # Create ckproxy symlink
    execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink 
        ckpool \$ENV{DESTDIR}${CMAKE_INSTALL_FULL_BINDIR}/ckproxy)
")

install(CODE "
    # Clean up symlink during uninstall
    file(REMOVE \$ENV{DESTDIR}${CMAKE_INSTALL_FULL_BINDIR}/ckproxy)
")

