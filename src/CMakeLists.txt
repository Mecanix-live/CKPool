
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)

# SHA-256 Acceleration
set(ASSEMBLY_OBJECTS)

if(HAVE_SHA_NI)

    find_package(OpenSSL REQUIRED)
    
    if(OpenSSL_FOUND)
        # Verify OpenSSL was built with SHA-NI support
        include(CheckCSourceCompiles)
        set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
        set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_LIBRARIES})
        
        check_c_source_compiles("
            #include <openssl/evp.h>
            #include <openssl/sha.h>
            int main() {
                #if defined(OPENSSL_CPUID_OBJ) && (OPENSSL_cpu_caps() & (1<<30))
                return 0;
                #else
                force_fail_because_no_sha_ni();
                #endif
            }"
            OPENSSL_HAS_SHA_NI)
        
        if(OPENSSL_HAS_SHA_NI)
            message(STATUS "Using OpenSSL with SHA-NI acceleration")
            add_definitions(-DUSE_OPENSSL_SHA_NI)
        else()
            message(WARNING "OpenSSL found but lacks SHA-NI support - falling back to native implementation")
            add_definitions(-DUSE_SHA_NI)
        endif()
    else()
        message(WARNING "OpenSSL not found - falling back to native SHA-NI implementation")
        add_definitions(-DUSE_SHA_NI)
    endif()

elseif(HAVE_AVX2)

    set(ASSEMBLY_FILE "${CMAKE_CURRENT_SOURCE_DIR}/sha256_code_release/sha256_avx2_rorx2.asm")
    if(EXISTS ${ASSEMBLY_FILE})
        set(ASSEMBLY_OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/sha256_avx2.o")
        add_custom_command(
            OUTPUT ${ASSEMBLY_OUTPUT}
            COMMAND yasm -f elf64 -X gnu -g dwarf2 -D LINUX -o ${ASSEMBLY_OUTPUT} ${ASSEMBLY_FILE}
            DEPENDS ${ASSEMBLY_FILE}
            COMMENT "Building AVX2 SHA256 implementation"
        )
        list(APPEND ASSEMBLY_OBJECTS ${ASSEMBLY_OUTPUT})
        add_definitions(-DUSE_AVX2)
    else()
        message(WARNING "AVX2 assembly file not found - skipping optimization")
    endif()

elseif(HAVE_AVX1)

    set(ASSEMBLY_FILE "${CMAKE_CURRENT_SOURCE_DIR}/sha256_code_release/sha256_avx1.asm")
    if(EXISTS ${ASSEMBLY_FILE})
        set(ASSEMBLY_OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/sha256_avx.o")
        add_custom_command(
            OUTPUT ${ASSEMBLY_OUTPUT}
            COMMAND yasm -f elf64 -X gnu -g dwarf2 -D LINUX -o ${ASSEMBLY_OUTPUT} ${ASSEMBLY_FILE}
            DEPENDS ${ASSEMBLY_FILE}
            COMMENT "Building AVX1 SHA256 implementation"
        )
         list(APPEND ASSEMBLY_OBJECTS ${ASSEMBLY_OUTPUT})
        add_definitions(-DUSE_AVX1)
    else()
        message(WARNING "AVX1 assembly file not found - skipping optimization")
    endif()

elseif(HAVE_SSE4)

    set(ASSEMBLY_FILE "${CMAKE_CURRENT_SOURCE_DIR}/sha256_code_release/sha256_sse4.asm")
    if(EXISTS ${ASSEMBLY_FILE})
        set(ASSEMBLY_OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/sha256_sse4.o")
        add_custom_command(
            OUTPUT ${ASSEMBLY_OUTPUT}
            COMMAND yasm -f elf64 -X gnu -g dwarf2 -D LINUX -o ${ASSEMBLY_OUTPUT} ${ASSEMBLY_FILE}
            DEPENDS ${ASSEMBLY_FILE}
            COMMENT "Building SSE4 SHA256 implementation"
        )
        list(APPEND ASSEMBLY_OBJECTS ${ASSEMBLY_OUTPUT})
        add_definitions(-DUSE_SSE4)
    else()
        message(WARNING "SSE4 assembly file not found - using scalar implementation")
    endif()
endif()

# Main library
add_library(ckpool_lib STATIC
    libckpool.c
    sha2.c
    ${ASSEMBLY_OBJECTS}
)

# Executables
add_executable(ckpool
    ckpool.c
    generator.c
    bitcoin.c
    stratifier.c
    connector.c
)

# Links
target_link_libraries(ckpool
    ckpool_lib 
    ${JANSSON_LIB} 
    ${PTHREAD_LIB} 
    ${M_LIB} 
    ${RT_LIB} 
    ${ZMQ_LIB}
    ${OPENSSL_LIBRARIES}
)

# Installation
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

