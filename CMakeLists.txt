cmake_minimum_required(VERSION 3.10)

project(ckpool VERSION 1.0.0 LANGUAGES C CXX)

# Compiler Optimization
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
if(NOT CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "")
	set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

# Enable ccache
find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
	set(CMAKE_C_COMPILER_LAUNCHER   "${CCACHE_PROGRAM}")
	set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
	message(STATUS "Found ccache: ${CCACHE_PROGRAM}")
endif()

# GNU standard installation directories
include(GNUInstallDirs)
set(CMAKE_INSTALL_PREFIX "/usr/local" CACHE PATH "Installation prefix")

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


# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Required compiler flags to check for SHA-NI
include(CheckCXXSourceRuns)
set(CMAKE_REQUIRED_FLAGS "-msha")

# Check if SHA-NI instructions are available
check_cxx_source_runs("
	#include <immintrin.h>
	int main() {
		__m128i a = _mm_sha256rnds2_epu32(_mm_setzero_si128(), _mm_setzero_si128(), _mm_setzero_si128());
		return 0;
	}"
	HAVE_SHA_NI)

if(HAVE_SHA_NI)
    message(STATUS "SHA-NI support detected: Enabling hardware acceleration.")
else()
    message(STATUS "SHA-NI not available: Falling back to OpenSSL SHA-256.")
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


# Subdirectory
add_subdirectory(src)


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

message(STATUS "\nConfigured ckpool ${PROJECT_VERSION}")
message(STATUS "==========================================")
message(STATUS "  prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  C compiler: ${CMAKE_C_COMPILER}")
message(STATUS "  C flags: ${CMAKE_C_FLAGS}")
message(STATUS "==========================================\n")
