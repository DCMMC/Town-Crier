set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} -fPIC -Wall")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS} -std=c++11")

###############################
#### list source code files
###############################
add_custom_command(
        OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/Enclave_u.c
        COMMAND ${SGX_EDGER8R} --untrusted ${TC_ROOT_DIR}/Enclave/Enclave.edl
        --search-path ${TC_ROOT_DIR}/Enclave
        --search-path ${SGX_SDK}/include
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

# Get the current working branch
execute_process(
        COMMAND git rev-parse --abbrev-ref HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_BRANCH
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Get the latest abbreviated commit hash of the working branch
execute_process(
        COMMAND git log -1 --format=%h
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_COMMIT_HASH
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

# generate version header
configure_file(
        ${CMAKE_SOURCE_DIR}/src/Common/version.h.in
        ${CMAKE_SOURCE_DIR}/src/Common/version.h
)

set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "Enclave_u.c; Enclave_u.h")

###############################
#### dependencies
###############################

find_package(Boost QUIET REQUIRED COMPONENTS program_options filesystem system)
find_package(Log4CXX REQUIRED)

# ###############################################################################
# grpc
# ###############################################################################

list(APPEND CMAKE_PREFIX_PATH "/opt/grpc" "/opt/protobuf")

find_package(Protobuf REQUIRED)
find_package(GRPC REQUIRED)

# Generated sources
set(PROTO_OUTDIR ${CMAKE_CURRENT_SOURCE_DIR}/services/generated)
set(PROTO_FILE ${CMAKE_CURRENT_SOURCE_DIR}/services/tc.proto)

file(MAKE_DIRECTORY ${PROTO_OUTDIR})

protobuf_generate_cpp(PROTO_SRCS
        PROTO_HDRS
        ${PROTO_OUTDIR}
        ${PROTO_FILE})

grpc_generate_cpp(GRPC_SRCS
        GRPC_HDRS
        ${PROTO_OUTDIR}
        ${PROTO_FILE})

set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "Enclave_u.c; Enclave_u.h")


###############################
#### targets
###############################

# (DCMMC) 最终就是生成这两个可执行文件
add_executable(tc
        tc.cpp
        attestation.cpp
        mbedtls_sgx_net.c
        Enclave_u.c
        ocalls.cpp
        debug.cpp
        converter.cpp
        utils.cpp
        types.cpp
        rpc.cpp
        ../Common/external/base64.cpp
        key_utils.cpp
        logging.cpp
        tc_exception.cpp
        config.cpp
        ${PROTO_SRCS}
        ${GRPC_SRCS})

add_executable(tc-keygen
        tc-keygen.cpp
        logging.cpp
        ../Common/external/base64.cpp
        converter.cpp
        Enclave_u.c
        ocalls.cpp
        utils.cpp
        mbedtls_sgx_net.c)

include_directories(
        ${Boost_INCLUDE_DIRS}
        ${SGXSDK_INCLUDE_DIRS}
        ${MBEDTLS_LIB_DIR}/include
        ${LOG4CXX_INCLUDE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/..
)

target_link_libraries(tc
        ${Boost_LIBRARIES}
        ${LOG4CXX_LIBRARY}
        ${SGX_URTS_LIBRARY} ${SGX_USVC_LIBRARY}
        gRPC::grpc++
        protobuf::libprotobuf
        -Wl,-rpath=/opt/grpc/lib:/opt/protobuf/lib # hardcode rpath for now.
        -lpthread -ldl)

target_link_libraries(tc-keygen
        ${SGX_URTS_LIBRARY} ${SGX_USVC_LIBRARY} ${Boost_LIBRARIES}
        ${LOG4CXX_LIBRARY}
        -lpthread -ldl)


# (DCMMC) 可执行文件依赖父目录中 Enclave 生成的 enclave 库
add_dependencies(tc enclave)
add_dependencies(tc-keygen enclave)

###############################
#### Output & Installtation
###############################
install(TARGETS tc tc-keygen DESTINATION bin)
install(FILES
        ${CMAKE_SOURCE_DIR}/src/logging.conf
        ${CMAKE_SOURCE_DIR}/config/config-privatenet-sim
        DESTINATION conf)

### a conditional target for tests

if(BUILD_TESTS)
    set(LIBGTESTDIR "${CMAKE_SOURCE_DIR}/src/vendor/gtest")

    FILE(GLOB TEST_SRC_FILES "test/*.cpp")

    add_executable(tc-test
            ${TEST_SRC_FILES}
            attestation.cpp
            utils.cpp
            debug.cpp
            Enclave_u.c
            ocalls.cpp
            logging.cpp
            mbedtls_sgx_net.c
            converter.cpp
            ../Common/external/base64.cpp
            types.cpp
            key_utils.cpp)

    target_include_directories(tc-test
            PRIVATE ${LIBGTESTDIR}/include)

    target_link_libraries(tc-test
            ${SGX_URTS_LIBRARY} ${SGX_USVC_LIBRARY} ${Boost_LIBRARIES}
            ${JSONCPP_LIBRARIES} ${CURL_LIBRARIES} ${JSONRPCCPP_LIBRARIES}
            ${LIBODB_LIBRARIES} ${MHD_LIBRARIES} ${SQLITE_LIBRARIES} ${Boost_LIBRARIES}
            ${LOG4CXX_LIBRARY}
            -lpthread -ldl
            gtest_main)

    add_dependencies(tc-test enclave)

    set_property(TARGET tc-test
            PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/src/Enclave)

endif(BUILD_TESTS)
