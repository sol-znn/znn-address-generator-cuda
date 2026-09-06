# Cross-platform build for znn-address-generator-cuda.
#
#   cmake -B build -DCMAKE_CUDA_ARCHITECTURES=86
#   cmake --build build --config Release
#
# Set CMAKE_CUDA_ARCHITECTURES to your GPU: 70 Volta, 75 Turing, 80/86 Ampere,
# 89 Ada, 90 Hopper.
#
# Pass -DZNN_VERSION=x.y.z to embed a version (as reported by --version);
# it defaults to the current development version otherwise.

cmake_minimum_required(VERSION 3.18)
project(znn_address_generator_cuda LANGUAGES CXX CUDA)

if(NOT DEFINED CMAKE_CUDA_ARCHITECTURES)
    set(CMAKE_CUDA_ARCHITECTURES 86)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CUDA_STANDARD 17)

add_executable(znn-address-generator-cuda main.cu)

if(DEFINED ZNN_VERSION)
    target_compile_definitions(znn-address-generator-cuda PRIVATE ZNN_VERSION="${ZNN_VERSION}")
endif()

if(NOT MSVC)
    target_compile_options(znn-address-generator-cuda PRIVATE $<$<COMPILE_LANGUAGE:CUDA>:-O3>)
endif()
