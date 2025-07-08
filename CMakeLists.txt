cmake_minimum_required(VERSION 3.10)

project (ckpool
	VERSION 1.0.0
	DESCRIPTION "Next-Gen Mining Stratum Server"
	LANGUAGES C)
	
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

# Required libraries
find_library(OpenSSL_LIB crypto)
find_library(JANSSON_LIB NAMES jansson libjansson)
find_library(RT_LIB rt)
find_library(M_LIB m)
find_library(PTHREAD_LIB pthread)
find_library(ZMQ_LIB zmq)

# Verify all libraries were found
foreach(LIB IN ITEMS OpenSSL JANSSON RT M PTHREAD ZMQ)
    if(NOT ${LIB}_LIB)
        message(FATAL_ERROR "${LIB} library not found")
    endif()
endforeach()

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
