
include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_BINARY_DIR}
)

# Main library
add_library(ckpool_lib STATIC
	libckpool.c
	sha2.c
)

# SHA-NI conf
if(HAVE_SHA_NI)
	target_compile_options(ckpool_lib PRIVATE -msha -msse4.1)
	target_compile_definitions(ckpool_lib PRIVATE USE_SHA_NI)
endif()

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
	OpenSSL::Crypto
)

# Installation
install(TARGETS ckpool
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Post-install hooks
install(CODE "
	execute_process(COMMAND setcap CAP_NET_BIND_SERVICE=+eip \$ENV{DESTDIR}${CMAKE_INSTALL_FULL_BINDIR}/ckpool)
")

