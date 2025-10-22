cmake_minimum_required(VERSION 3.28)
project(TFLiteCppApi_Test)

set(CMAKE_BUILD_TYPE Release)
set(CMAKE_C_COMPILER "gcc")
set(CMAKE_CXX_COMPILER "g++")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenCV REQUIRED)
if(NOT OpenCV_FOUND)
    message(FATAL_ERROR "OpenCV not found")
endif()

set(CMAKE_INSTALL_RPATH "${CMAKE_CURRENT_SOURCE_DIR}/lib")
set(CMAKE_BUILD_WITH_INSTALL_RPATH ON)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/lib)

add_executable(run_test main.cpp)

target_compile_definitions(run_test
    PRIVATE
    PROJECT_ROOT_PATH="${CMAKE_SOURCE_DIR}"
)

target_link_libraries(run_test
    PRIVATE
    ${OpenCV_LIBS}
    tensorflowlite
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/libflatbuffers.a
)
