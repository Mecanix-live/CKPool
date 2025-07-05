cmake_minimum_required(VERSION 3.10)

project(ckpool VERSION 1.0.0 LANGUAGES C CXX)

# Compiler Optimization
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
if(NOT CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "")
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

# GNU standard installation directories
include(GNUInstallDirs)
set(CMAKE_INSTALL_PREFIX "/usr/local" CACHE PATH "Installation prefix")
option(ENABLE_SHARED "Build shared libraries" OFF)
option(ENABLE_STATIC "Build static libraries" ON)
option(ENABLE_ASM "Enable assembly optimizations" ON)

# System extensions
add_compile_definitions(_GNU_SOURCE)

# Header checks
include(CheckIncludeFile)
foreach(header
    stdio.h stdlib.h fcntl.h sys/time.h unistd.h dirent.h
    ctype.h errno.h byteswap.h string.h time.h fenv.h
    endian.h sys/endian.h arpa/inet.h sys/poll.h syslog.h
    alloca.h pthread.h stdio.h math.h signal.h sys/prctl.h
    sys/types.h sys/socket.h sys/stat.h linux/un.h netdb.h
    stdint.h netinet/in.h netinet/tcp.h sys/ioctl.h getopt.h
    sys/epoll.h libpq-fe.h postgresql/libpq-fe.h grp.h
    gsl/gsl_math.h gsl/gsl_cdf.h openssl/x509.h openssl/hmac.h
    zmq.h
)
    string(TOUPPER ${header} HEADER_UPPER)
    string(REPLACE "." "_" HEADER_UPPER ${HEADER_UPPER})
    string(REPLACE "/" "_" HEADER_UPPER ${HEADER_UPPER})
    check_include_file(${header} HAVE_${HEADER_UPPER})
endforeach()

find_package(OpenSSL REQUIRED)

if(ENABLE_ASM)
    find_program(YASM_EXECUTABLE yasm)
    if(YASM_EXECUTABLE)
        set(YASM_FOUND TRUE)
        message(STATUS "Found YASM: ${YASM_EXECUTABLE}")
    else()
        set(YASM_FOUND FALSE)
        message(STATUS "YASM not found - disabling assembly optimizations")
    endif()
endif()


if(YASM_FOUND)

    include(CheckCXXSourceRuns)
    
     check_cxx_source_runs("
        #include <immintrin.h>
		int main() {
			__m128i a = _mm_sha256rnds2_epu32(_mm_setzero_si128(), 
											_mm_setzero_si128(), 
											_mm_setzero_si128());
			return 0;
		}"
		HAVE_SHA_NI)
    
    check_cxx_source_runs("
        #include <immintrin.h>
        int main() {
            __m256i a = _mm256_set1_epi32(1);
            __m256i b = _mm256_set1_epi32(2);
            __m256i c = _mm256_add_epi32(a, b);
            return 0;
        }"
        HAVE_AVX2)
    
    check_cxx_source_runs("
        #include <immintrin.h>
        int main() {
            __m128i a = _mm_set1_epi32(1);
            __m128i b = _mm_set1_epi32(2);
            __m128i c = _mm_add_epi32(a, b);
            return 0;
        }"
        HAVE_AVX1)

    check_cxx_source_runs("
        #include <smmintrin.h>
        int main() {
            __m128i a = _mm_set1_epi32(1);
            __m128i b = _mm_set1_epi32(2);
            __m128i c = _mm_add_epi32(a, b);
            return 0;
        }"
        HAVE_SSE4)
endif()


# Verify OpenSSL actually uses SHA-NI
if(HAVE_SHA_NI AND OpenSSL_FOUND)
    check_c_source_runs("
        #include <openssl/evp.h>
        #include <openssl/sha.h>
        int main() {
            EVP_MD_CTX *ctx = EVP_MD_CTX_new();
            const EVP_MD *md = EVP_sha256();
            EVP_DigestInit_ex(ctx, md, NULL);
            #ifdef OPENSSL_CPUID_OBJ
            if (!(OPENSSL_cpu_caps() & (1 << 30)))  // SHA_NI capability bit
                return 1;
            #endif
            return 0;
        }"
        OPENSSL_HAS_SHA_NI)
endif()


if(HAVE_SHA_NI AND OPENSSL_HAS_SHA_NI)
    message(STATUS "Using OpenSSL with SHA-NI acceleration")
    add_compile_definitions(USE_OPENSSL_SHA_NI=1)
elseif(HAVE_SHA_NI)
    message(STATUS "Enabling SHA-NI (Intel SHA Extensions) optimizations")
    add_compile_definitions(USE_SHA_NI=1)
elseif(HAVE_AVX2)
    add_compile_definitions(USE_AVX2=1)
    message(STATUS "Enabling AVX2 optimizations")
elseif(HAVE_AVX1)
    add_compile_definitions(USE_AVX1=1)
    message(STATUS "Enabling AVX1 optimizations")
elseif(HAVE_SSE4)
    add_compile_definitions(USE_SSE4=1)
    message(STATUS "Enabling SSE4 optimizations")
endif()


# Required libraries
find_library(JANSSON_LIB NAMES jansson libjansson)
find_library(RT_LIB rt)
find_library(M_LIB m)
find_library(PTHREAD_LIB pthread)
find_library(ZMQ_LIB zmq)

if(NOT JANSSON_LIB)
    message(FATAL_ERROR "Required library Jansson (libjansson-dev) not found")
endif()
if(NOT RT_LIB)
    message(FATAL_ERROR "Required library rt not found")
endif()
if(NOT M_LIB)
    message(FATAL_ERROR "Required library m not found")
endif()
if(NOT PTHREAD_LIB)
    message(FATAL_ERROR "Required library pthread not found")
endif()
if(NOT ZMQ_LIB)
    message(FATAL_ERROR "Required library ZeroMQ (libzmq3-dev) not found")
endif()

# Subdirectories
add_subdirectory(src)

# Installation files
#install(FILES ckpool.conf ckproxy.conf LICENSE README.md
#    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/ckpool)

#install(FILES ckpool.conf DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/ckpool)
    
# Uninstall target
set(CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}" CACHE PATH "Install prefix for uninstall")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/uninstall.cmake"
    @ONLY
)
add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/uninstall.cmake
)

message("\nConfigured ckpool ${PROJECT_VERSION}")
message("==========================================")
message("Installation directories:")
message("  prefix: ${CMAKE_INSTALL_PREFIX}")
message("  bindir: ${CMAKE_INSTALL_BINDIR}")
message("  libdir: ${CMAKE_INSTALL_LIBDIR}")
message("  includedir: ${CMAKE_INSTALL_INCLUDEDIR}")
message("\nBuild options:")
message("  C compiler: ${CMAKE_C_COMPILER}")
message("  C flags: ${CMAKE_C_FLAGS}")
message("  Static libs: ${ENABLE_STATIC}")
message("  Assembly optimizations: ${ENABLE_ASM}")
message("==========================================\n")
