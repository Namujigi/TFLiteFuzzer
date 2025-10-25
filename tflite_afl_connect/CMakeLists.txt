# Debug Type build
cmake_minimum_required(VERSION 3.28)
project(TFLiteCppApi_Test)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_C_COMPILER "/AFLplusplus/afl-clang-lto")
set(CMAKE_CXX_COMPILER "/AFLplusplus/afl-clang-lto++")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenCV REQUIRED)
if(NOT OpenCV_FOUND)
    message(FATAL_ERROR "OpenCV not found")
endif()

set(CMAKE_INSTALL_RPATH "${CMAKE_CURRENT_SOURCE_DIR}/lib_debug")
set(CMAKE_BUILD_WITH_INSTALL_RPATH ON)

include_directories(${CMAKE_SOURCE_DIR}/../tflite_cpp_api_test/include)
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/lib_debug)

add_executable(debug_mode main.cpp)

target_link_libraries(debug_mode
    PRIVATE
    ${OpenCV_LIBS}
    tensorflowlite
    ${CMAKE_CURRENT_SOURCE_DIR}/lib_debug/libflatbuffers.a
)