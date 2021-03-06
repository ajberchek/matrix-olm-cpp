cmake_minimum_required(VERSION 3.1)

project(matrix_olm_wrapper CXX)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} \
        -std=c++1z \
        -Wall \
        -Wextra \
        -Werror \
        -pipe \
        -pedantic \
        -Wunreachable-code")

    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
        execute_process(COMMAND ${CMAKE_CXX_COMPILER} -dumpversion OUTPUT_VARIABLE GCC_VERSION)

        if (GCC_VERSION VERSION_GREATER 4.9)
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fdiagnostics-color=always" )
        endif()
    endif()

    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fdiagnostics-color=always" )
    endif()
endif()

if(NOT APPLE AND NOT MSVC)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
endif()

#
# libolm
#
include(Olm)

#
# libsodium
#
include(Findsodium)

#
# gtest
#
find_package(GTest REQUIRED)

file(DOWNLOAD "https://github.com/nlohmann/json/releases/download/v3.1.2/json.hpp" 
	${PROJECT_SOURCE_DIR}/deps/json.hpp 
	EXPECTED_HASH SHA256=fbdfec4b4cf63b3b565d09f87e6c3c183bdd45c5be1864d3fcb338f6f02c1733)

include_directories(deps)
include_directories(src)
include_directories(include/MatrixOlmWrapper)
include_directories(SYSTEM sodium_INCLUDE_DIR)
include_directories(${GTEST_INCLUDE_DIRS})
include_directories("$ENV{GMOCK_DIR}/include")
set(SRC src/MatrixOlmWrapper.cpp)

add_library(matrix_olm_wrapper ${SRC})
add_dependencies(matrix_olm_wrapper Olm)
target_link_libraries(matrix_olm_wrapper olm ${sodium_LIBRARY_RELEASE})

add_executable(test_wrapper tests/TestWrapper.cpp)
target_link_libraries(test_wrapper matrix_olm_wrapper ${GTEST_LIBRARIES} ${GMOCK_LIBRARIES} pthread)
add_test(TestWrapper test_wrapper)

add_executable(test_utils tests/TestUtils.cpp)
target_link_libraries(test_utils matrix_olm_wrapper ${GTEST_LIBRARIES} ${GMOCK_LIBRARIES} pthread)
add_test(TestUtils test_utils)